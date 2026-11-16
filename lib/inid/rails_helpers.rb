# frozen_string_literal: true

require "erb"

module InID
  # Helpers for Rails controllers and views. Plain modules (no Rails needed to load them); the
  # Railtie includes them.
  module Rails
    SCRIPT_URL = "https://cdn.jsdelivr.net/npm/@inid/js@0.1/dist/inid.global.js"

    module ControllerHelpers
      def self.included(base)
        base.extend(ClassMethods)
        base.helper_method(:inid_auth, :inid_user, :inid_signed_in?) if base.respond_to?(:helper_method)
      end

      module ClassMethods
        # require_inid! role: "admin", only: [:edit]  (a before_action)
        def require_inid!(role: nil, permission: nil, entrance: nil, **filter_options)
          before_action(**filter_options) { require_inid!(role: role, permission: permission, entrance: entrance) }
        end
      end

      # Who is signed in (set by InID::Middleware; read from the cookies without it)
      def inid_auth
        @inid_auth ||= request.env["inid"] || InID.client.auth(request.env)
      end

      def inid_user = inid_auth.user
      def inid_signed_in? = inid_auth.signed_in?

      # Sends whoever isn't signed in to sign in (and back here); 403 without the role or
      # permission asked
      def require_inid!(role: nil, permission: nil, entrance: nil)
        unless inid_signed_in?
          to = [["return_to", request.fullpath]]
          to << ["entrance", entrance] if entrance
          return redirect_to("#{InID.client.api_path}/signin?#{URI.encode_www_form(to)}", allow_other_host: false)
        end
        return if inid_user.has?(role: role&.to_s, permission: permission&.to_s)

        head :forbidden
      end
    end

    module ViewHelpers
      # <inid-sign-in> and the @inid/js script: inid_sign_in(app_name: "Mi App")
      def inid_sign_in(app_name: nil, return_to: nil, entrance: nil, script: true)
        attrs = { "app-name" => app_name, "return-to" => return_to, "entrance" => entrance }.compact
        attrs["api-path"] = InID.client.api_path if InID.client.api_path != "/api/inid"
        html = +""
        html << inid_script_tag if script
        html << "<inid-sign-in#{attrs.map { |k, v| %( #{k}="#{ERB::Util.html_escape(v)}") }.join}></inid-sign-in>"
        html.respond_to?(:html_safe) ? html.html_safe : html
      end

      def inid_script_tag
        tag = %(<script src="#{SCRIPT_URL}" defer></script>)
        tag.respond_to?(:html_safe) ? tag.html_safe : tag
      end
    end
  end
end
