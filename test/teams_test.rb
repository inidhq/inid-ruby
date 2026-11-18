# frozen_string_literal: true

require "test_helper"

# The active team: in the user, in has?, in protect rules, and the team / teams routes
class TeamsTest < Minitest::Test
  include InIDTestHelpers

  def test_team_in_the_user
    user = InID::User.from_claims(FakeInID.claims(600, roles: ["member"], permissions: ["invoices:read"],
                                                       team: FakeInID::TEAM.merge("permissions" => ["invoices:write", 7])))
    assert_equal FakeInID::TEAM, user.team.to_h
    assert_equal FakeInID::TEAM, user.to_h["team"]
    assert user.has?(team_role: "admin")
    refute user.has?(team_role: "member")
    # A permission counts from the team's role and from the app role
    assert user.has?(permission: "invoices:write")
    assert user.has?(permission: "invoices:read")
    refute user.has?(permission: "billing:write")
    assert user.has?(role: "member", team_role: "admin", permission: "invoices:write")
    refute user.has?(role: "admin", team_role: "admin")
    assert InID::Auth.new(InID::Session.new(user: user, expires_at: 0, claims: {})).has?(team_role: "admin")
    refute InID::Auth.new.has?(team_role: "admin")
  end

  def test_missing_or_malformed_team_is_nil
    [nil, { "id" => "t1" }, { "id" => 1, "role" => "admin" }, ["t1"], "t1"].each do |claim|
      claims = FakeInID.claims(600, permissions: ["a"])
      claims["team"] = claim unless claim.nil?
      user = InID::User.from_claims(claims)
      assert_nil user.team, claim.inspect
      assert_nil user.to_h["team"]
      refute user.has?(team_role: "admin")
      assert user.has?(permission: "a")
    end
    bare = InID::User.from_claims({ "sub" => "u", "team" => { "id" => "t", "role" => "viewer", "slug" => 3, "permissions" => "x" } })
    assert_equal({ "id" => "t", "slug" => "", "name" => "", "role" => "viewer", "permissions" => [] }, bare.team.to_h)
  end

  def test_team_role_rules
    @protect = [{ path: "/team-admin", team_role: "admin" }, { path: "/team-owner", teamRole: "owner" }]
    visit("/team-admin", cookie: session_cookie)
    assert_equal 403, last_response.status
    visit("/team-admin", cookie: session_cookie(600, team: FakeInID::TEAM))
    assert_equal 200, last_response.status
    visit("/team-owner", cookie: session_cookie(600, team: FakeInID::TEAM))
    assert_equal 403, last_response.status
  end

  def test_switching_team
    visit("/api/inid/team", method: "POST", body: '{"teamId":"t1"}')
    assert_equal [401, '{"error":"not_signed_in"}'], [last_response.status, last_response.body]
    cookie = "#{session_cookie}; __inid_refresh=rt_1"

    visit("/api/inid/team", method: "POST", cookie: cookie, body: '{"teamId":"t1"}')
    assert_equal 200, last_response.status
    assert_equal "t1", JSON.parse(last_response.body)["user"]["team"]["id"]
    token = @fake.last("/oauth/token")
    assert_equal({ "grant_type" => "refresh_token", "refresh_token" => "rt_1", "team" => "t1" }, @fake.form(token))
    assert token[:headers]["Authorization"].start_with?("Basic ")
    assert set_cookie("__inid_refresh").start_with?("__inid_refresh=rt_new;")
    assert set_cookie("__inid_session")

    # null: back to their own account
    visit("/api/inid/team", method: "POST", cookie: cookie, body: '{"teamId":null}')
    assert_equal 200, last_response.status
    assert_nil JSON.parse(last_response.body)["user"]["team"]
    assert_equal "", @fake.form(@fake.last("/oauth/token"))["team"]

    # A team they aren't in: 400, cookies untouched
    visit("/api/inid/team", method: "POST", cookie: cookie, body: '{"teamId":"t9"}')
    assert_equal [400, '{"error":"not_a_member"}', []], [last_response.status, last_response.body, set_cookies]
    visit("/api/inid/team", method: "POST", cookie: cookie, body: '{"teamId":5}')
    assert_equal 400, last_response.status

    # The session is over at InID
    @fake.token_status = 400
    visit("/api/inid/team", method: "POST", cookie: cookie, body: '{"teamId":"t1"}')
    assert_equal [401, '{"error":"not_signed_in"}'], [last_response.status, last_response.body]
    assert_includes set_cookie("__inid_session"), "Max-Age=0"
  end

  def test_teams_forwarder
    visit("/api/inid/teams")
    assert_equal 401, last_response.status

    visit("/api/inid/teams", cookie: session_cookie)
    assert_equal [200, '{"teams":[{"id":"t1"}]}'], [last_response.status, last_response.body]
    call = @fake.last("/v1/users/u1/teams")
    assert_equal ["GET", "Bearer sk_test_secret", nil], [call[:method], call[:headers]["Authorization"], call[:body]]

    visit("/api/inid/teams", method: "POST", cookie: session_cookie, body: '{"name":"Beta"}')
    assert_equal [201, '{"id":"t2"}'], [last_response.status, last_response.body]
    call = @fake.last("/v1/users/u1/teams")
    assert_equal ["POST", "application/json", '{"name":"Beta"}'], [call[:method], call[:headers]["Content-Type"], call[:body]]

    visit("/api/inid/teams/t1/members/m1", method: "DELETE", cookie: session_cookie)
    assert_equal 404, last_response.status # InID's answer, passed on
    assert_equal "DELETE", @fake.last("/v1/users/u1/teams/t1/members/m1")[:method]
    visit("/api/inid/teams/boom", cookie: session_cookie)
    assert_equal 502, last_response.status

    count = @fake.requests.count { |r| r[:path].start_with?("/v1/users/u1/teams") }
    %w[/api/inid/teams/a/b/c/d/e /api/inid/teams/a.b /api/inid/teams/].each do |path|
      visit(path, cookie: session_cookie)
      assert_equal 404, last_response.status, path
    end
    visit("/api/inid/teams", method: "PUT", cookie: session_cookie)
    assert_equal 404, last_response.status
    assert_equal count, @fake.requests.count { |r| r[:path].start_with?("/v1/users/u1/teams") }
  end
end
