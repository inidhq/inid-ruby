# frozen_string_literal: true

module InID
  # Rack middleware: answers InID's routes under the api path, keeps the session fresh,
  # guards protected paths and leaves who is signed in at env["inid"] (an InID::Auth).
  #
  #   use InID::Middleware, protect: ["/dashboard", %r{\A/reports}, { path: "/admin", role: "admin", entrance: "team" }]
  #
  # protect: path strings (a path and its subpaths), regexps, hashes with path:, role:,
  # permission:, entrance:, or a proc taking the env. routes: false leaves the api path to the app.
  # Any other option (publishable_key:, secret_key:, issuer:…) builds the client, or pass client:.
  class Middleware
    def initialize(app, protect: [], routes: true, client: nil, **client_options)
      @app = app
      @protect = protect.is_a?(Proc) ? protect : Array(protect).map { |rule| Rule.from(rule) }
      @routes = routes
      @client = client || (client_options.empty? ? InID.client : Client.new(**client_options))
    end

    attr_reader :client

    def call(env)
      api_path = client.api_path
      path = "#{env["SCRIPT_NAME"]}#{env["PATH_INFO"]}"
      if path == api_path || path.start_with?("#{api_path}/")
        return @routes ? client.call(env) : @app.call(env)
      end

      query = Util.parse_query(env["QUERY_STRING"])
      # Back from Google on the app's own domain: Google's answer is for InID, so the person
      # goes straight on there
      if query["state"].to_s.start_with?("inidg_") && (query.key?("code") || query.key?("error"))
        return Reply.redirect("#{client.issuer}/oauth/google/callback?#{env["QUERY_STRING"]}", status: 307)
      end

      begin
        result = client.read_session(env["HTTP_COOKIE"], renew: true, secure: client.secure?(env))
      rescue NetworkError
        return Reply.response(502, { "content-type" => "text/plain; charset=utf-8" }, "InID is unavailable")
      end
      session = result.session
      matched = rules_for(env, path)
      if session.nil? && matched.any?
        to = [["return_to", env["QUERY_STRING"].to_s.empty? ? path : "#{path}?#{env["QUERY_STRING"]}"]]
        entrance = matched.find(&:entrance)&.entrance
        to << ["entrance", entrance] if entrance
        return Reply.redirect("#{client.origin(env)}#{api_path}/signin?#{URI.encode_www_form(to)}", result.set_cookies, status: 307)
      end
      if session && matched.any? { |rule| !session.user.has?(role: rule.role, permission: rule.permission) }
        # Signed in, without the role or permission the path needs
        return Reply.response(403, { "content-type" => "text/plain; charset=utf-8" }, "Forbidden", result.set_cookies)
      end

      env["inid"] = Auth.new(session)
      # The rest of this request sees the renewed cookies too
      env["HTTP_COOKIE"] = result.cookie_header if result.cookie_header
      status, headers, body = @app.call(env)
      [status, Reply.add_cookies(headers, result.set_cookies), body]
    end

    private

    def rules_for(env, path)
      return @protect.call(env) ? [Rule.new("/")] : [] if @protect.is_a?(Proc)

      @protect.select { |rule| rule.match?(path) }
    end
  end

  # A path (and its subpaths) or a pattern that needs someone signed in, and maybe a role or
  # permission; entrance: the door its sign-in goes through
  Rule = Struct.new(:path, :role, :permission, :entrance) do
    def self.from(rule)
      case rule
      when Rule then rule
      when String, Regexp then new(rule)
      when Hash
        h = rule.transform_keys(&:to_sym)
        new(h[:path], h[:role]&.to_s, h[:permission]&.to_s, h[:entrance]&.to_s)
      else raise ArgumentError, "InID protect rule must be a String, Regexp or Hash: #{rule.inspect}"
      end
    end

    def match?(given)
      return path.match?(given) if path.is_a?(Regexp)

      given == path || given.start_with?(path.end_with?("/") ? path : "#{path}/")
    end
  end
end
