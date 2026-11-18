# frozen_string_literal: true

require "test_helper"

class ConfigTest < Minitest::Test
  def test_missing_or_malformed_keys_fail_at_startup
    error = assert_raises(InID::ConfigError) { InID::Client.new(publishable_key: "nope", secret_key: "sk_x") }
    assert_match(/INID_PUBLISHABLE_KEY/, error.message)
    error = assert_raises(InID::ConfigError) { InID::Client.new(publishable_key: "pk_x", secret_key: "nope") }
    assert_match(/INID_SECRET_KEY/, error.message)
  end

  def test_env_and_defaults
    old = ENV.to_h
    ENV["INID_PUBLISHABLE_KEY"] = "pk_test_env"
    ENV["INID_SECRET_KEY"] = "sk_test_env"
    ENV.delete("INID_ISSUER")
    client = InID::Client.new
    assert_equal ["pk_test_env", "https://id.inid.co", "/api/inid", "openid profile email phone"],
                 [client.publishable_key, client.issuer, client.api_path, client.scope]
  ensure
    ENV.replace(old)
  end
end

# 1. signin
class SignInTest < Minitest::Test
  include InIDTestHelpers

  def test_redirect_with_every_parameter_pkce_and_flow_cookie
    visit("/api/inid/signin?return_to=%2Fdashboard%3Ftab%3D1&ui_locales=en&login_hint=ana&entrance=team")
    assert_equal 302, last_response.status
    assert_equal "no-store", last_response.headers["cache-control"]
    uri = URI(location)
    assert_equal "#{FakeInID::ISSUER}/oauth/authorize", "#{uri.scheme}://#{uri.host}#{uri.path}"
    q = URI.decode_www_form(uri.query).to_h
    assert_equal({ "client_id" => "pk_test_app", "redirect_uri" => "https://app.example/api/inid/callback",
                   "response_type" => "code", "scope" => "openid profile email phone", "code_challenge_method" => "S256",
                   "ui_locales" => "en", "login_hint" => "ana", "entrance" => "team" },
                 q.except("state", "nonce", "code_challenge"))
    cookie = set_cookie("__inid_flow_#{q["state"]}")
    ["; Path=/api/inid", "; Max-Age=600", "; HttpOnly", "; SameSite=Lax", "; Secure"].each { |a| assert_includes cookie, a }

    params, flow, = start_sign_in("return_to=/dashboard")
    assert_equal "/dashboard", flow["returnTo"]
    assert_equal [params["state"], params["nonce"]], [flow["state"], flow["nonce"]]
    assert_equal InID::Util.b64url(OpenSSL::Digest::SHA256.digest(flow["verifier"])), params["code_challenge"]
    assert_equal 22, params["state"].length
  end

  def test_return_to_is_sanitized
    ["%2F%2Fevil.com", "%2F%5Cevil.com", "https%3A%2F%2Fevil.com", ""].each do |bad|
      _, flow, = start_sign_in("return_to=#{bad}")
      assert_equal "/", flow["returnTo"], bad
    end
  end

  def test_prompt_login_after_signing_out
    params, = start_sign_in("return_to=/", cookie: "__inid_out=1")
    assert_equal "login", params["prompt"]
    params, = start_sign_in("return_to=/")
    assert_nil params["prompt"]
  end

  def test_embed
    params, flow, = start_sign_in("return_to=/home&display=embed&page=/signin-page")
    assert_equal %w[embed login], [params["display"], params["prompt"]]
    assert_equal [true, "/signin-page", "/home"], [flow["embed"], flow["page"], flow["returnTo"]]

    # Back from Google inside the frame: on with the same sign-in at InID
    resume = URI.encode_www_form_component("request=r1&session=s1&from=google&lang=es&evil=1")
    visit("/api/inid/signin?display=embed&continue=#{resume}")
    assert_equal "#{FakeInID::ISSUER}/oauth/authorize/continue?request=r1&session=s1&from=google&lang=es&display=embed", location
  end
end

# 2. callback
class CallbackTest < Minitest::Test
  include InIDTestHelpers

  def test_exchanges_the_code_and_signs_in
    _, flow, flow_cookie = start_sign_in("return_to=/dashboard")
    @fake.next_nonce = flow["nonce"]
    visit("/api/inid/callback?code=c1&state=#{flow["state"]}", cookie: "#{flow_cookie}; __inid_out=1")
    assert_equal [302, "/dashboard"], [last_response.status, location]

    request = @fake.last("/oauth/token")
    assert_equal({ "grant_type" => "authorization_code", "code" => "c1",
                   "redirect_uri" => "https://app.example/api/inid/callback", "code_verifier" => flow["verifier"] },
                 @fake.form(request))
    assert_equal "Basic #{["pk_test_app:sk_test_secret"].pack("m0")}", request[:headers]["Authorization"]

    assert_includes set_cookie("__inid_session"), "Max-Age=2592000"
    refute set_cookie("__inid_session").start_with?("__inid_session=;")
    assert set_cookie("__inid_refresh").start_with?("__inid_refresh=rt_new;")
    assert_includes set_cookie("__inid_out"), "Max-Age=0"
    assert_includes set_cookie("__inid_flow_#{flow["state"]}"), "Max-Age=0"
  end

  def test_wrong_nonce_is_refused
    _, flow, flow_cookie = start_sign_in("return_to=/dashboard")
    @fake.next_nonce = "someone-elses"
    visit("/api/inid/callback?code=c2&state=#{flow["state"]}", cookie: flow_cookie)
    assert_equal 400, last_response.status
    assert_nil set_cookie("__inid_session")
  end

  def test_state_mismatch_goes_home
    _, _, flow_cookie = start_sign_in("return_to=/dashboard")
    asked = @fake.requests.count { |r| r[:path] == "/oauth/token" }
    visit("/api/inid/callback?code=c3&state=other", cookie: flow_cookie)
    assert_equal [302, "/"], [last_response.status, location]
    assert_equal asked, @fake.requests.count { |r| r[:path] == "/oauth/token" }
  end

  def test_embedded_flow_leaves_the_frame
    _, flow, flow_cookie = start_sign_in("return_to=%2Fa%3C%2Fscript%3E&display=embed&page=/login")
    @fake.next_nonce = flow["nonce"]
    visit("/api/inid/callback?code=c1&state=#{flow["state"]}", cookie: flow_cookie)
    assert_equal 200, last_response.status
    escaped = "\"/a#{"\\"}u003c/script>\""
    assert_equal %(<!doctype html><meta charset="utf-8"><script>(window.top || window).location.replace(#{escaped})</script>),
                 last_response.body
    assert set_cookie("__inid_session")

    # Back from Google: to the page with the form, which goes on where InID left it
    visit("/api/inid/callback?inid_continue=abc&state=#{flow["state"]}", cookie: flow_cookie)
    assert_equal [302, "/login?inid_continue=abc"], [last_response.status, location]
  end
end

# 3. renewal
class RenewalTest < Minitest::Test
  include InIDTestHelpers

  def test_renews_near_expiry_and_the_same_request_sees_it
    ending = session_cookie(30)
    visit("/", cookie: "#{ending}; __inid_refresh=rt_old; other=1")
    assert_equal({ "grant_type" => "refresh_token", "refresh_token" => "rt_old" }, @fake.form(@fake.last("/oauth/token")))
    assert @seen[:auth].signed_in?
    renewed = set_cookie("__inid_session").split(";").first
    refute_equal ending, renewed
    assert set_cookie("__inid_refresh").start_with?("__inid_refresh=rt_new;")
    [renewed, "__inid_refresh=rt_new", "other=1"].each { |c| assert_includes @seen[:cookie], c }
  end

  def test_fresh_session_is_not_renewed
    visit("/", cookie: "#{session_cookie(600)}; __inid_refresh=rt")
    assert @seen[:auth].signed_in?
    assert_nil @fake.last("/oauth/token")
    assert_empty set_cookies
  end

  def test_a_4xx_ends_the_session
    @fake.token_status = 400
    visit("/", cookie: "#{session_cookie(30)}; __inid_refresh=rt_old")
    refute @seen[:auth].signed_in?
    %w[__inid_session __inid_refresh].each { |n| assert_includes set_cookie(n), "Max-Age=0" }
    assert_equal "", @seen[:cookie]
  end

  def test_network_error_keeps_what_is_still_valid
    @fake.token_down = true
    visit("/", cookie: "#{session_cookie(30)}; __inid_refresh=rt_old")
    assert @seen[:auth].signed_in?
    assert_empty set_cookies
    visit("/", cookie: "#{session_cookie(-5)}; __inid_refresh=rt_old")
    refute @seen[:auth].signed_in?

    @fake.token_down = false
    @fake.token_status = 503
    visit("/", cookie: "#{session_cookie(30)}; __inid_refresh=rt_old")
    assert @seen[:auth].signed_in?
  end
end

# 4. signout, 5. /session, sessions
class SignOutAndSessionTest < Minitest::Test
  include InIDTestHelpers

  def test_signout_revokes_clears_and_marks_signed_out
    visit("/api/inid/signout", method: "POST", cookie: "__inid_session=x; __inid_refresh=rt_1")
    assert_equal [200, '{"ok":true}', "no-store"], [last_response.status, last_response.body, last_response.headers["cache-control"]]
    revoke = @fake.last("/oauth/revoke")
    assert_equal({ "token" => "rt_1", "token_type_hint" => "refresh_token" }, @fake.form(revoke))
    assert revoke[:headers]["Authorization"].start_with?("Basic ")
    assert_equal 3, revoke[:timeout]
    %w[__inid_session __inid_refresh].each { |n| assert_includes set_cookie(n), "Max-Age=0" }
    assert set_cookie("__inid_out").start_with?("__inid_out=1;")
    assert_includes set_cookie("__inid_out"), "Max-Age=2592000"
  end

  def test_session_json_is_camel_case
    visit("/api/inid/session", cookie: session_cookie)
    assert_equal "no-store", last_response.headers["cache-control"]
    body = JSON.parse(last_response.body)
    assert_equal({ "id" => "u1", "firstName" => "Ana", "lastName" => "Gómez", "name" => "Ana Gómez", "email" => "ana@correo.co",
                   "emailVerified" => true, "phone" => "+573001234567", "roles" => ["staff"], "permissions" => ["orders:read"],
                   "publicMetadata" => { "plan" => "pro" }, "team" => nil }, body["user"])
    assert_equal "#{FakeInID::ISSUER}/account?client_id=pk_test_app", body["accountUrl"]

    visit("/api/inid/session")
    assert_equal({ "user" => nil, "accountUrl" => "#{FakeInID::ISSUER}/account?client_id=pk_test_app" }, JSON.parse(last_response.body))

    bare = { "iss" => FakeInID::ISSUER, "aud" => "pk_test_app", "sub" => "u2", "exp" => Time.now.to_i + 600, "name" => "Solo" }
    visit("/api/inid/session", cookie: "__inid_session=#{FakeInID.sign(bare)}")
    assert_equal({ "id" => "u2", "firstName" => nil, "lastName" => nil, "name" => "Solo", "email" => nil, "emailVerified" => false,
                   "phone" => nil, "roles" => [], "permissions" => [], "publicMetadata" => {}, "team" => nil },
                 JSON.parse(last_response.body)["user"])

    # The active team
    visit("/api/inid/session", cookie: session_cookie(600, team: FakeInID::TEAM.merge("permissions" => ["invoices:write", 3])))
    assert_equal FakeInID::TEAM, JSON.parse(last_response.body)["user"]["team"]

    # Renewal happens here too
    visit("/api/inid/session", cookie: "#{session_cookie(10)}; __inid_refresh=rt")
    assert set_cookie("__inid_refresh")

    visit("/api/inid/nothing")
    assert_equal [404, '{"error":"not_found"}'], [last_response.status, last_response.body]
  end

  def test_sessions
    visit("/api/inid/sessions")
    assert_equal 401, last_response.status
    visit("/api/inid/sessions", cookie: session_cookie)
    assert_equal [["s1", false], ["s2", true], ["s3", false]],
                 JSON.parse(last_response.body)["sessions"].map { |s| [s["id"], s["current"]] }
    visit("/api/inid/sessions?others=1", method: "DELETE", cookie: session_cookie)
    assert_equal '{"ended":2}', last_response.body
    assert_equal %w[/v1/users/u1/sessions/s1 /v1/users/u1/sessions/s3],
                 @fake.requests.select { |r| r[:method] == "DELETE" }.map { |r| r[:path] }
    visit("/api/inid/sessions/s9", method: "DELETE", cookie: session_cookie)
    assert_equal '{"ended":1}', last_response.body
    assert_equal "Bearer sk_test_secret", @fake.last("/v1/users/u1/sessions/s9")[:headers]["Authorization"]
  end
end
