# frozen_string_literal: true

require "test_helper"

# The Rails helpers, on stand-ins for a controller and a view (Rails itself isn't needed)
class RailsHelpersTest < Minitest::Test
  class Controller
    Request = Struct.new(:env, :fullpath)
    attr_reader :request, :redirected, :status

    def self.filters = (@filters ||= [])
    def self.before_action(**options, &block) = filters << [options, block]

    include InID::Rails::ControllerHelpers

    def initialize(env, fullpath = "/admin?x=1")
      @request = Request.new(env, fullpath)
    end

    def redirect_to(to, **) = (@redirected = to)
    def head(status) = (@status = status)
  end

  class AdminController < Controller
    require_inid! role: "admin", only: [:index]
  end

  def setup
    InID.client = InID::Client.new(publishable_key: "pk_test_app", secret_key: "sk_test_secret", issuer: FakeInID::ISSUER,
                                   transport: FakeInID.new)
    @ana = InID::Session.new(user: InID::User.from_claims(FakeInID.claims(600)), expires_at: 0, claims: {})
  end

  def teardown
    InID.client = nil
  end

  def test_controller_helpers
    signed_in = Controller.new({ "inid" => InID::Auth.new(@ana) })
    assert signed_in.inid_signed_in?
    assert_equal "u1", signed_in.inid_user.id
    signed_in.require_inid!(role: "staff")
    assert_nil signed_in.status
    signed_in.require_inid!(role: "admin")
    assert_equal :forbidden, signed_in.status

    anonymous = Controller.new({ "inid" => InID::Auth.new })
    anonymous.require_inid!(entrance: "team")
    assert_equal "/api/inid/signin?return_to=%2Fadmin%3Fx%3D1&entrance=team", anonymous.redirected

    # Without the middleware: read from the cookies
    from_cookies = Controller.new({ "HTTP_COOKIE" => "__inid_session=#{FakeInID.sign(FakeInID.claims(600))}" })
    assert from_cookies.inid_signed_in?
  end

  def test_before_action_macro
    options, filter = AdminController.filters.last
    assert_equal({ only: [:index] }, options)
    controller = AdminController.new({ "inid" => InID::Auth.new(@ana) })
    controller.instance_exec(&filter)
    assert_equal :forbidden, controller.status
  end

  def test_view_helper
    view = Object.new.extend(InID::Rails::ViewHelpers)
    assert_equal '<script src="https://cdn.jsdelivr.net/npm/@inid/js@0.1/dist/inid.global.js" defer></script>' \
                 '<inid-sign-in app-name="Mi &quot;App&quot;"></inid-sign-in>',
                 view.inid_sign_in(app_name: 'Mi "App"')
    assert_equal '<inid-sign-in app-name="Mi App" entrance="team"></inid-sign-in>', view.inid_sign_in(app_name: "Mi App", entrance: "team", script: false)
  end

  def test_railtie_stays_out_without_rails
    refute defined?(InID::Railtie)
  end
end
