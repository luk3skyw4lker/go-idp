package saml

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/gofiber/fiber/v2"
	"github.com/luk3skyw4lker/go-idp/internal/config"
	"github.com/luk3skyw4lker/go-idp/internal/session"
	"github.com/luk3skyw4lker/go-idp/internal/storage/postgres"

	dsig "github.com/russellhaering/goxmldsig"
)

type Handlers struct {
	cfg   config.Config
	store *postgres.Store

	// We generate a dev signing keypair/certificate for SAML signatures at runtime.
	// For testing, we keep the signing key and metadata cert consistent within the running process.
	signingCtx interface {
		SignEnveloped(el *etree.Element) (*etree.Element, error)
	}
	signingCertDER []byte
}

func NewHandlers(cfg config.Config, store *postgres.Store) *Handlers {
	ks := dsig.RandomKeyStoreForTest()
	ctx := dsig.NewDefaultSigningContext(ks)

	// Best-effort extraction of the generated certificate for metadata.
	// Most implementations return (*rsa.PrivateKey, []byte, error).
	_, certDER, err := ks.GetKeyPair()
	if err != nil {
		certDER = []byte{}
	}

	return &Handlers{
		cfg:         cfg,
		store:       store,
		signingCtx:  ctx,
		signingCertDER: certDER,
	}
}

func (h *Handlers) Metadata(c *fiber.Ctx) error {
	entityID := h.cfg.PublicIssuerURL
	location := h.cfg.PublicIssuerURL + "/saml/sso"

	certB64 := base64.StdEncoding.EncodeToString(h.signingCertDER)

	// Minimal SP-initiated SSO metadata.
	metadata := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>%s</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="%s"/>
    <NameIDFormat>%s</NameIDFormat>
  </IDPSSODescriptor>
</EntityDescriptor>`, xmlEscape(entityID), xmlEscape(certB64), xmlEscape(location), xmlEscape("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"))

	c.Type("application/samlmetadata+xml")
	return c.SendString(metadata)
}

func (h *Handlers) SSO(c *fiber.Ctx) error {
	switch c.Method() {
	case fiber.MethodGet:
		pendingID := c.Query("pending_saml_id")
		if pendingID == "" {
			return c.Status(fiber.StatusBadRequest).SendString("missing pending_saml_id")
		}
		return h.resume(c, pendingID)
	case fiber.MethodPost:
		return h.handlePost(c)
	default:
		return c.Status(fiber.StatusMethodNotAllowed).SendString("method not allowed")
	}
}

func (h *Handlers) handlePost(c *fiber.Ctx) error {
	ctx := c.Context()
	samlRequestB64 := c.FormValue("SAMLRequest")
	relayState := c.FormValue("RelayState")

	if samlRequestB64 == "" {
		return c.Status(fiber.StatusBadRequest).SendString("missing SAMLRequest")
	}

	xmlBytes, err := decodeSAMLRequest(samlRequestB64)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).SendString("invalid SAMLRequest")
	}

	authnReq, err := parseAuthnRequest(xmlBytes)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).SendString("invalid AuthnRequest")
	}

	userID, ok := session.UserIDFromContext(c)

	pendingID := randomToken(24)
	var relayStatePtr *string
	if relayState != "" {
		relayStatePtr = &relayState
	}

	req := postgres.PendingSamlRequest{
		PendingID:      pendingID,
		SPIssuer:       authnReq.Issuer,
		RelayState:     relayStatePtr,
		SAMLRequestXML: string(xmlBytes),
		ExpiresAt:      time.Now().Add(10 * time.Minute),
	}

	// Persist pending state so login can resume.
	if err := h.store.PutPendingSamlRequest(ctx, req); err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("failed to persist pending SAML request")
	}

	// If already logged in, resume immediately.
	if ok && userID != "" {
		return h.buildAndReturnResponse(c, req, userID)
	}

	return c.Redirect(fmt.Sprintf("/login?pending_saml_id=%s", urlQueryEscape(pendingID)))
}

func (h *Handlers) resume(c *fiber.Ctx, pendingID string) error {
	ctx := c.Context()
	userID, ok := session.UserIDFromContext(c)
	if !ok || userID == "" {
		return c.Status(fiber.StatusUnauthorized).SendString("not authenticated")
	}

	req, err := h.store.ConsumePendingSamlRequest(ctx, pendingID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).SendString("invalid/expired pending SAML request")
	}

	return h.buildAndReturnResponse(c, req, userID)
}

func (h *Handlers) buildAndReturnResponse(c *fiber.Ctx, pending postgres.PendingSamlRequest, userID string) error {
	_ = context.Background()

	authnReq, err := parseAuthnRequest([]byte(pending.SAMLRequestXML))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("failed to parse AuthnRequest")
	}

	sp, err := h.store.GetSamlSPByIssuer(c.Context(), pending.SPIssuer)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).SendString("unknown Service Provider")
	}

	idpEntityID := h.cfg.PublicIssuerURL
	acsURL := sp.AcsURL
	audience := ""
	if sp.AudienceURI != nil {
		audience = *sp.AudienceURI
	}

	now := time.Now().UTC()
	assertionID := "assertion-" + randomToken(16)
	responseID := "response-" + randomToken(16)

	// Build Response with a signed Assertion (signed assertion is good enough for many test SPs).
	response := etree.NewElement("samlp:Response")
	response.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	response.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	response.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
	response.CreateAttr("ID", responseID)
	response.CreateAttr("InResponseTo", authnReq.ID)
	response.CreateAttr("Version", "2.0")
	response.CreateAttr("IssueInstant", now.Format(time.RFC3339))
	response.CreateAttr("Destination", acsURL)

	issuerEl := etree.NewElement("saml:Issuer")
	issuerEl.SetText(idpEntityID)
	response.AddChild(issuerEl)

	statusEl := etree.NewElement("samlp:Status")
	statusCode := etree.NewElement("samlp:StatusCode")
	statusCode.CreateAttr("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")
	statusEl.AddChild(statusCode)
	response.AddChild(statusEl)

	// Assertion
	assertion := etree.NewElement("saml:Assertion")
	assertion.CreateAttr("ID", assertionID)
	assertion.CreateAttr("IssueInstant", now.Format(time.RFC3339))
	assertion.CreateAttr("Version", "2.0")

	aIssuerEl := etree.NewElement("saml:Issuer")
	aIssuerEl.SetText(idpEntityID)
	assertion.AddChild(aIssuerEl)

	subjectEl := etree.NewElement("saml:Subject")
	nameID := etree.NewElement("saml:NameID")
	nameID.SetText(userID)
	if sp.NameIDFormat != nil && *sp.NameIDFormat != "" {
		nameID.CreateAttr("Format", *sp.NameIDFormat)
	} else {
		nameID.CreateAttr("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")
	}
	subjectEl.AddChild(nameID)

	subjectConf := etree.NewElement("saml:SubjectConfirmation")
	subjectConf.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	subjectConfData := etree.NewElement("saml:SubjectConfirmationData")
	subjectConfData.CreateAttr("Recipient", acsURL)
	subjectConfData.CreateAttr("NotOnOrAfter", now.Add(5*time.Minute).Format(time.RFC3339))
	subjectConf.AddChild(subjectConfData)
	subjectEl.AddChild(subjectConf)
	assertion.AddChild(subjectEl)

	conditionsEl := etree.NewElement("saml:Conditions")
	conditionsEl.CreateAttr("NotBefore", now.Add(-1*time.Minute).Format(time.RFC3339))
	conditionsEl.CreateAttr("NotOnOrAfter", now.Add(5*time.Minute).Format(time.RFC3339))
	if audience != "" {
		ar := etree.NewElement("saml:AudienceRestriction")
		aud := etree.NewElement("saml:Audience")
		aud.SetText(audience)
		ar.AddChild(aud)
		conditionsEl.AddChild(ar)
	}
	assertion.AddChild(conditionsEl)

	authnStmt := etree.NewElement("saml:AuthnStatement")
	authnStmt.CreateAttr("AuthnInstant", now.Format(time.RFC3339))
	authnStmt.CreateAttr("SessionIndex", "session-"+randomToken(8))

	authnCtx := etree.NewElement("saml:AuthnContext")
	authnCtxClass := etree.NewElement("saml:AuthnContextClassRef")
	authnCtxClass.SetText("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")
	authnCtx.AddChild(authnCtxClass)
	authnStmt.AddChild(authnCtx)
	assertion.AddChild(authnStmt)

	// Sign the assertion.
	signedAssertion, err := h.signingCtx.SignEnveloped(assertion)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("failed to sign SAML assertion")
	}

	response.AddChild(signedAssertion)

	doc := etree.NewDocument()
	doc.SetRoot(response)
	xmlOut, err := doc.WriteToString()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("failed to serialize SAML response")
	}

	samlRespB64 := base64.StdEncoding.EncodeToString([]byte(xmlOut))
	relayState := ""
	if pending.RelayState != nil {
		relayState = *pending.RelayState
	}

	html := fmt.Sprintf(`<!doctype html>
<html><body>
<form method="post" action="%s">
  <input type="hidden" name="SAMLResponse" value="%s"/>
  <input type="hidden" name="RelayState" value="%s"/>
</form>
<script>document.forms[0].submit();</script>
</body></html>`, htmlEscape(acsURL), htmlEscape(samlRespB64), htmlEscape(relayState))

	return c.Type("text/html; charset=utf-8").SendString(html)
}

// --- SAML helpers ---

type AuthnRequest struct {
	ID     string
	Issuer string
}

func parseAuthnRequest(xmlBytes []byte) (AuthnRequest, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		return AuthnRequest{}, err
	}
	root := doc.Root()
	if root == nil {
		return AuthnRequest{}, errors.New("missing root")
	}
	if localName(root.Tag) != "AuthnRequest" {
		return AuthnRequest{}, fmt.Errorf("unexpected root element: %s", root.Tag)
	}
	id := root.SelectAttrValue("ID", "")

	var issuerText string
	// etree selection can miss namespaced elements; iterate and match on local tag name.
	for _, el := range doc.FindElements(".//*") {
		if localName(el.Tag) == "Issuer" {
			issuerText = strings.TrimSpace(el.Text())
			break
		}
	}

	if issuerText == "" {
		return AuthnRequest{}, errors.New("missing Issuer in AuthnRequest")
	}

	return AuthnRequest{ID: id, Issuer: issuerText}, nil
}

func decodeSAMLRequest(b64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}

	trim := bytes.TrimSpace(raw)
	if bytes.HasPrefix(trim, []byte("<")) {
		return raw, nil
	}

	// Try DEFLATE/Zlib (some test SPs still send deflated payloads).
	r, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	decoded, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

func localName(tag string) string {
	if i := strings.IndexByte(tag, ':'); i >= 0 {
		return tag[i+1:]
	}
	return tag
}

func randomToken(nBytes int) string {
	b := make([]byte, nBytes)
	_, err := rand.Read(b)
	if err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func urlQueryEscape(s string) string {
	return strings.ReplaceAll(s, "+", "%20")
}

func xmlEscape(s string) string {
	return strings.ReplaceAll(s, "&", "&amp;")
}

func htmlEscape(s string) string {
	// etree/Go templates handle escaping; we keep this minimal.
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

