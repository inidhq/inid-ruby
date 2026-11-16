# frozen_string_literal: true

require "test_helper"

# 7. webhooks
class WebhookTest < Minitest::Test
  BODY = '{"type":"session.ended","sub":"u1","sid":"s1","created_at":"2026-11-16T00:00:00Z"}'

  def sign(secret, at) = "t=#{at},v1=#{OpenSSL::HMAC.hexdigest("SHA256", secret, "#{at}.#{BODY}")}"

  def test_valid
    event = InID.verify_webhook(BODY, sign("whsec_test", Time.now.to_i), secret: "whsec_test")
    assert_equal %w[session.ended u1 s1], [event["type"], event["sub"], event["sid"]]
    client = InID::Client.new(publishable_key: "pk_x", secret_key: "sk_x", webhook_secret: "whsec_test", transport: FakeInID.new)
    assert_equal "session.ended", client.verify_webhook(BODY, sign("whsec_test", Time.now.to_i))["type"]
  end

  def test_rejected
    now = Time.now.to_i
    {
      "wrong secret" => sign("whsec_other", now),
      "too old" => sign("whsec_test", now - 301),
      "future" => sign("whsec_test", now + 301),
      "malformed" => "garbage",
      "no v1" => "t=#{now}",
      "no t" => "v1=#{"0" * 64}",
      "empty" => "",
      "nil" => nil,
      "not hex" => "t=#{now},v1=zz"
    }.each do |name, header|
      assert_raises(InID::InvalidSignature, name) { InID.verify_webhook(BODY, header, secret: "whsec_test") }
    end
    assert_raises(InID::InvalidSignature) { InID.verify_webhook('{"type":"x"}', sign("whsec_test", now), secret: "whsec_test") }
    assert_raises(InID::ConfigError) { InID.verify_webhook(BODY, sign("whsec_test", now), secret: nil) }
  end
end

# 8. ID token verification
class VerifyTest < Minitest::Test
  def setup
    @now = Time.now
    @fake = FakeInID.new
    @client = InID::Client.new(publishable_key: "pk_test_app", secret_key: "sk_test_secret", issuer: FakeInID::ISSUER,
                               transport: @fake, clock: -> { @now })
  end

  def token(expires_in = 600, **extra) = FakeInID.sign(FakeInID.claims(expires_in, **extra))

  def test_good_token
    session = @client.verify_bearer("Bearer #{token}")
    assert_equal "u1", session.user.id
    InID.client = @client
    assert_equal "u1", InID.verify_bearer(token).user.id
  ensure
    InID.client = nil
  end

  def test_rejected
    other = OpenSSL::PKey::RSA.generate(2048)
    parts = token.split(".")
    tampered = [parts[0], InID::Util.b64url('{"iss":"x"}'), parts[2]].join(".")
    no_sub = FakeInID.claims(600).tap { |c| c.delete("sub") }
    {
      "wrong aud" => token(aud: "pk_test_other"),
      "wrong iss" => token(iss: "https://evil.example"),
      "no sub" => FakeInID.sign(no_sub),
      "bad signature" => FakeInID.sign(FakeInID.claims(600), key: other),
      "tampered" => tampered,
      "unknown kid" => FakeInID.sign(FakeInID.claims(600), kid: "k-unknown"),
      "alg HS256" => FakeInID.sign(FakeInID.claims(600), alg: "HS256"),
      "expired" => token(-1),
      "not a jwt" => "abc.def",
      "garbage" => "a.b.c"
    }.each { |name, t| assert_nil @client.verify_bearer(t), name }
  end

  def test_expired_still_verifies_flagged
    checked = @client.verify_id_token(token(-1))
    assert checked[:expired]
    assert_nil @client.verify_id_token(token, nonce: "n1")
    refute_nil @client.verify_id_token(token(600, nonce: "n1"), nonce: "n1")
  end

  def test_key_cache
    3.times { @client.verify_bearer(token) }
    assert_equal 1, @fake.jwks_hits
    unknown = ->(kid) { @client.verify_bearer(FakeInID.sign(FakeInID.claims(600), kid: kid)) }
    unknown.("new1") # the first unknown kid is looked up at once (InID just rotated)
    assert_equal 2, @fake.jwks_hits
    unknown.("new2")
    assert_equal 2, @fake.jwks_hits, "at most once a second"
    @now += 2
    unknown.("new2")
    assert_equal 3, @fake.jwks_hits
    @now += 2
    unknown.("new2")
    assert_equal 3, @fake.jwks_hits, "a missed kid is remembered"
    @now += 7200
    @client.verify_bearer(token)
    assert_equal 4, @fake.jwks_hits, "kept an hour"
  end
end
