# frozen_string_literal: true

require "minitest/autorun"
require "rack"
require "rack/test"
require "inid"

# A fake InID behind the client's transport: it serves a JWKS and signs ID tokens with a
# test RSA key, and records what the SDK asked.
class FakeInID
  ISSUER = "https://id.inid.example"
  KEY = OpenSSL::PKey::RSA.generate(2048)

  attr_accessor :token_status, :token_down, :next_nonce
  attr_reader :requests, :jwks_hits

  def initialize
    @requests = []
    @jwks_hits = 0
    @token_status = 200
  end

  def call(method, url, headers: {}, body: nil, timeout: 10)
    uri = URI(url)
    @requests << { method: method, path: uri.path, query: uri.query, headers: headers, body: body, timeout: timeout }
    case [method, uri.path]
    when ["GET", "/.well-known/jwks.json"]
      @jwks_hits += 1
      n = InID::Util.b64url(KEY.n.to_s(2))
      e = InID::Util.b64url(KEY.e.to_s(2))
      reply(200, { keys: [{ kty: "EC", kid: "ec1" }, { kty: "RSA", kid: "k1", alg: "RS256", n: n, e: e }] })
    when ["POST", "/oauth/token"]
      raise InID::NetworkError, "connection refused" if token_down
      return reply(token_status, { error: "invalid_grant" }) unless token_status == 200

      claims = self.class.claims(600)
      claims["nonce"] = next_nonce if next_nonce
      reply(200, { id_token: self.class.sign(claims), refresh_token: "rt_new", access_token: "at", expires_in: 600 })
    when ["POST", "/oauth/revoke"] then reply(200, {})
    when ["GET", "/v1/users/u1/sessions"]
      reply(200, { sessions: [{ id: "s1", createdAt: "a", lastActiveAt: "b", device: "Mac" },
                              { id: "s2", createdAt: "c", lastActiveAt: "d", device: nil },
                              { id: "s3", createdAt: "e", lastActiveAt: "f", device: nil }] })
    when ["DELETE", "/v1/users/u1/sessions/s1"], ["DELETE", "/v1/users/u1/sessions/s3"], ["DELETE", "/v1/users/u1/sessions/s9"]
      reply(200, { ended: 1 })
    when ["PUT", "/v1/users/u1/role"] then reply(200, { id: "u1", role: "admin" })
    when ["GET", "/v1/users/nobody"] then reply(404, { error: "user_not_found" })
    else reply(404, { error: "not_found" })
    end
  end

  def form(request) = URI.decode_www_form(request[:body]).to_h
  def last(path) = requests.reverse.find { |r| r[:path] == path }

  def self.claims(expires_in, **extra)
    now = Time.now.to_i
    {
      "iss" => ISSUER, "aud" => "pk_test_app", "sub" => "u1", "sid" => "s2", "exp" => now + expires_in, "iat" => now,
      "given_name" => "Ana", "family_name" => "Gómez", "email" => "ana@correo.co", "email_verified" => true,
      "phone_number" => "+573001234567", "roles" => ["staff"], "permissions" => ["orders:read"],
      "public_metadata" => { "plan" => "pro" }
    }.merge(extra.transform_keys(&:to_s))
  end

  def self.sign(claims, key: KEY, kid: "k1", alg: "RS256")
    data = [{ alg: alg, kid: kid, typ: "JWT" }, claims].map { |part| InID::Util.b64url(JSON.generate(part)) }.join(".")
    "#{data}.#{InID::Util.b64url(key.sign("SHA256", data))}"
  end

  private

  def reply(status, body) = InID::Response.new(status, JSON.generate(body))
end

module InIDTestHelpers
  include Rack::Test::Methods

  def setup
    @fake = FakeInID.new
    @client = InID::Client.new(publishable_key: "pk_test_app", secret_key: "sk_test_secret", issuer: "#{FakeInID::ISSUER}/",
                               app_url: "https://app.example", webhook_secret: "whsec_test", transport: @fake)
    @protect = []
    @seen = {}
  end

  def app
    seen = @seen
    page = lambda do |env|
      seen[:called] = true
      seen[:auth] = env["inid"]
      seen[:cookie] = env["HTTP_COOKIE"]
      [200, { "content-type" => "text/plain" }, ["page"]]
    end
    InID::Middleware.new(page, client: @client, protect: @protect, **(@middleware_options || {}))
  end

  # A request with exactly these cookies (not rack-test's jar)
  def visit(path, cookie: "", method: "GET")
    @seen.clear
    custom_request(method, path, {}, { "HTTP_COOKIE" => cookie })
    last_response
  end

  def set_cookies = Array(last_response.headers["set-cookie"]).flat_map { |c| c.split("\n") }
  def set_cookie(name) = set_cookies.find { |c| c.start_with?("#{name}=") }
  def location = last_response.headers["location"]

  def session_cookie(expires_in = 600, **extra) = "__inid_session=#{FakeInID.sign(FakeInID.claims(expires_in, **extra))}"

  # Starts a sign-in: the authorize query, the flow and its cookie
  def start_sign_in(query, cookie: "")
    visit("/api/inid/signin?#{query}", cookie: cookie)
    assert_equal 302, last_response.status
    params = URI.decode_www_form(URI(location).query).to_h
    value = set_cookie("__inid_flow_#{params["state"]}").split(";").first.split("=", 2).last
    [params, JSON.parse(InID::Util.b64url_decode(value)), "__inid_flow_#{params["state"]}=#{value}"]
  end
end
