# frozen_string_literal: true

require "test_helper"

# 6. the gate
class GateTest < Minitest::Test
  include InIDTestHelpers

  def setup
    super
    @protect = ["/dashboard", { path: "/admin", role: "admin", entrance: "team" }, { path: %r{\A/orders}, permission: "orders:read" },
                { path: "/panel" }]
  end

  def test_not_signed_in_goes_to_sign_in_with_return_to_and_entrance
    visit("/admin/users?x=1")
    assert_equal [307, "https://app.example/api/inid/signin?return_to=%2Fadmin%2Fusers%3Fx%3D1&entrance=team"], [last_response.status, location]
    refute @seen[:called]
    visit("/dashboard")
    assert_equal "https://app.example/api/inid/signin?return_to=%2Fdashboard", location
  end

  def test_subpaths_and_patterns
    visit("/dashboard/a/b")
    assert_equal 307, last_response.status
    visit("/dashboardx")
    assert @seen[:called]
    refute @seen[:auth].signed_in?
    visit("/orders7")
    assert_equal 307, last_response.status
  end

  def test_roles_and_permissions
    visit("/admin", cookie: session_cookie)
    assert_equal [403, "Forbidden"], [last_response.status, last_response.body]
    refute @seen[:called]

    visit("/orders/7", cookie: session_cookie)
    auth = @seen[:auth]
    assert_equal [200, "u1", true, false, true], [last_response.status, auth.user_id, auth.has?(role: "staff"), auth.has?(role: "admin"), auth.has?]
    assert_equal "Ana Gómez", auth.user.name
    assert auth.user.has?(role: "staff", permission: "orders:read")
    refute auth.user.has?(role: "staff", permission: "x")

    # A rule with only a path: anyone signed in
    visit("/panel/x", cookie: session_cookie)
    assert_equal 200, last_response.status
    refute InID::Auth.new.has?
  end

  def test_google_return
    visit("/?state=inidg_abc&code=g&scope=email")
    assert_equal [307, "#{FakeInID::ISSUER}/oauth/google/callback?state=inidg_abc&code=g&scope=email"], [last_response.status, location]
    visit("/?state=inidg_abc&error=access_denied")
    assert_equal 307, last_response.status
    visit("/?state=other&code=g")
    assert @seen[:called]
  end

  def test_proc
    @protect = ->(env) { env["PATH_INFO"] == "/anything" }
    visit("/anything")
    assert_equal 307, last_response.status
  end

  def test_routes_false
    @middleware_options = { routes: false }
    visit("/api/inid/session")
    assert @seen[:called]
  end

  def test_renewed_cookies_reach_the_page_response
    visit("/", cookie: "#{session_cookie(30)}; __inid_refresh=rt_old")
    assert_equal "page", last_response.body
    assert set_cookie("__inid_session")
    assert set_cookie("__inid_refresh")
  end

  def test_app_api_helpers
    assert_equal({ "id" => "u1", "role" => "admin" }, @client.set_role("u1", "admin"))
    assert_equal({ "role" => "admin" }, JSON.parse(@fake.last("/v1/users/u1/role")[:body]))
    error = assert_raises(InID::APIError) { @client.get_user("nobody") }
    assert_equal ["user_not_found", 404], [error.code, error.status]
  end
end
