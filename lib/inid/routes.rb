# frozen_string_literal: true

require "json"
require "openssl"

module InID
  # Rack responses that work on Rack 2 and 3
  module Reply
    module_function

    def rack3? = !defined?(::Rack::RELEASE) || ::Rack::RELEASE.to_i >= 3

    # set-cookie: an array on Rack 3, newline-joined on Rack 2
    def add_cookies(headers, cookies)
      return headers if cookies.empty?

      key = headers.key?("Set-Cookie") ? "Set-Cookie" : "set-cookie"
      existing = headers[key]
      existing = existing.split("\n") if existing.is_a?(String)
      all = Array(existing) + cookies
      headers[key] = rack3? ? all : all.join("\n")
      headers
    end

    def response(status, headers, body, cookies = [])
      [status, add_cookies(headers, cookies), [body]]
    end

    def json(status, body, cookies = [])
      response(status, { "content-type" => "application/json", "cache-control" => "no-store" }, JSON.generate(body), cookies)
    end

    def redirect(to, cookies = [], status: 302)
      response(status, { "location" => to, "cache-control" => "no-store", "content-type" => "text/plain" }, "", cookies)
    end

    # A tiny page that sends the whole window on, out of InID's embedded form
    def leave_frame(to, cookies = [])
      target = JSON.generate(to).gsub("<", '\\' + "u003c")
      page = %(<!doctype html><meta charset="utf-8"><script>(window.top || window).location.replace(#{target})</script>)
      response(200, { "content-type" => "text/html; charset=utf-8", "cache-control" => "no-store" }, page, cookies)
    end
  end

  # The app's routes under api_path: signin, callback, signout, session, sessions, team, teams
  class Routes
    TEAMS_REST = %r{\A(/[\w-]{1,80}){0,4}\z}

    def initialize(client)
      @client = client
    end

    def call(env)
      api_path = @client.api_path
      path = "#{env["SCRIPT_NAME"]}#{env["PATH_INFO"]}"
      action = path.start_with?("#{api_path}/") ? path[(api_path.length + 1)..] : ""
      method = env["REQUEST_METHOD"]
      query = Util.parse_query(env["QUERY_STRING"])
      if method == "GET" && action == "signin" then sign_in(env, query)
      elsif method == "GET" && action == "callback" then callback(env, query)
      elsif method == "POST" && action == "signout" then sign_out(env)
      elsif action == "sessions" || action.start_with?("sessions/") then sessions(env, method, action, query)
      elsif method == "POST" && action == "team" then switch_team(env)
      elsif action == "teams" || action.start_with?("teams/") then teams(env, method, action)
      elsif method == "GET" && action == "session" then session(env)
      else Reply.json(404, { "error" => "not_found" })
      end
    rescue NetworkError
      Reply.json(502, { "error" => "inid_unavailable" })
    end

    private

    def cookies(env) = Util.parse_cookies(env["HTTP_COOKIE"])

    def sign_in(env, query)
      issuer = @client.issuer
      # display=embed: InID's form inside the app's own page (<inid-sign-in>)
      embed = query["display"] == "embed"
      # Back from Google, the frame goes on with the same sign-in (its flow cookie stays)
      if embed && query.key?("continue")
        given = Util.parse_query(query["continue"])
        kept = %w[request session from lang].filter_map { |k| [k, given[k]] if given[k] && !given[k].empty? }
        return Reply.redirect("#{issuer}/oauth/authorize/continue?#{URI.encode_www_form(kept + [%w[display embed]])}")
      end

      flow = { "state" => Util.random(16), "nonce" => Util.random(16), "verifier" => Util.random(32),
               "returnTo" => Util.safe_return(query["return_to"]) }
      if embed
        # page: where the form is, to go on there after Google
        page = query["page"].to_s.empty? ? query["return_to"] : query["page"]
        flow.merge!("embed" => true, "page" => Util.safe_return(page))
      end
      origin = @client.origin(env)
      params = {
        "client_id" => @client.publishable_key,
        "redirect_uri" => "#{origin}#{@client.api_path}/callback",
        "response_type" => "code",
        "scope" => @client.scope,
        "state" => flow["state"],
        "nonce" => flow["nonce"],
        "code_challenge" => Util.b64url(OpenSSL::Digest::SHA256.digest(flow["verifier"])),
        "code_challenge_method" => "S256"
      }
      %w[ui_locales login_hint prompt entrance].each { |k| params[k] = query[k] if query[k] && !query[k].empty? }
      # In the page, someone still clicks to go in: never signed in by just loading it
      params.merge!("display" => "embed", "prompt" => "login") if embed
      # Right after signing out of the app, InID asks too: they chose to leave
      params["prompt"] = "login" if cookies(env).key?(Client::COOKIE_OUT)
      # One cookie per sign-in (named by its state): two at once don't overwrite each other
      flow_cookie = Util.cookie("#{Client::COOKIE_FLOW}_#{flow["state"]}", Util.b64url(JSON.generate(flow)),
                                Client::FLOW_MAX_AGE, @client.api_path, origin.start_with?("https://"))
      Reply.redirect("#{issuer}/oauth/authorize?#{URI.encode_www_form(params)}", [flow_cookie])
    end

    def callback(env, query)
      origin = @client.origin(env)
      secure = origin.start_with?("https://")
      state = query["state"].to_s
      flow_name = state.match?(/\A[\w-]{1,64}\z/) ? "#{Client::COOKIE_FLOW}_#{state}" : Client::COOKIE_FLOW
      clear_flow = Util.cookie(flow_name, "", 0, @client.api_path, secure)
      flow = cookies(env)[flow_name]&.then { |raw| Util.json_part(raw) }
      flow = nil unless flow.is_a?(Hash) && flow["state"].is_a?(String)

      # Back from Google, a sign-in that started in the app's page goes on in it: back to that
      # page, whose form opens where InID left it. The flow cookie stays for its code.
      if query.key?("inid_continue") && flow && flow["embed"] && state == flow["state"]
        page = URI.parse(Util.safe_return(flow["page"]))
        page.query = URI.encode_www_form(Util.parse_query(page.query).merge("inid_continue" => query["inid_continue"]))
        return Reply.redirect(page.to_s)
      end

      # From InID's form inside the page, the whole page goes on (not just its frame)
      go = ->(to, set) { flow && flow["embed"] ? Reply.leave_frame(to, set) : Reply.redirect(to, set) }
      code = query["code"]
      if flow.nil? || code.to_s.empty? || state != flow["state"]
        return go.(Util.safe_return(flow && flow["returnTo"]), [clear_flow])
      end

      begin
        tokens = @client.token(grant_type: "authorization_code", code: code,
                               redirect_uri: "#{origin}#{@client.api_path}/callback", code_verifier: flow["verifier"])
      rescue APIError => e
        return Reply.json(e.status.to_i >= 500 ? 502 : 400, { "error" => e.code })
      end
      checked = @client.verify_id_token(tokens["id_token"], nonce: flow["nonce"])
      return Reply.json(400, { "error" => "invalid_id_token" }) if checked.nil? || checked[:expired]

      go.(Util.safe_return(flow["returnTo"]),
          [clear_flow, *@client.session_cookies(tokens, secure), Util.cookie(Client::COOKIE_OUT, "", 0, "/", secure)])
    end

    def sign_out(env)
      secure = @client.secure?(env)
      refresh = cookies(env)[Client::COOKIE_REFRESH]
      # The sign-in ends at InID too (best effort); the person's InID stays signed in
      if refresh
        begin
          @client.post_form("/oauth/revoke", { token: refresh, token_type_hint: "refresh_token" }, timeout: 3)
        rescue NetworkError
          nil
        end
      end
      Reply.json(200, { "ok" => true },
                 @client.clear_cookies(secure) + [Util.cookie(Client::COOKIE_OUT, "1", Client::COOKIE_MAX_AGE, "/", secure)])
    end

    def session(env)
      result = @client.read_session(env["HTTP_COOKIE"], renew: true, secure: @client.secure?(env))
      Reply.json(200, {
                   "user" => result.session&.user&.to_h,
                   "accountUrl" => "#{@client.issuer}/account?#{URI.encode_www_form(client_id: @client.publishable_key)}"
                 }, result.set_cookies)
    end

    def body_of(env, limit = 64 * 1024)
      input = env["rack.input"]
      return "" unless input

      input.rewind if input.respond_to?(:rewind)
      input.read(limit).to_s
    end

    # The person's active team: POST team { "teamId" } (null: their own account). InID renews
    # the session with it, so the new cookies (and this answer) say the team.
    def switch_team(env)
      secure = @client.secure?(env)
      refresh = cookies(env)[Client::COOKIE_REFRESH]
      current = @client.read_session(env["HTTP_COOKIE"], secure: secure).session
      return Reply.json(401, { "error" => "not_signed_in" }) unless current && refresh

      given = begin
        JSON.parse(body_of(env))
      rescue JSON::ParserError
        {}
      end
      asked = given.is_a?(Hash) ? given["teamId"] : nil
      return Reply.json(400, { "error" => "invalid_request" }) unless asked.nil? || asked.is_a?(String)

      begin
        tokens = @client.token(grant_type: "refresh_token", refresh_token: refresh, team: asked.to_s)
        renewed = @client.verify_id_token(tokens["id_token"])
        raise APIError.new("invalid_id_token", 400) unless renewed
      rescue APIError => e
        # The session itself is over; anything else (a team they aren't in) leaves it as it was
        return Reply.json(401, { "error" => "not_signed_in" }, @client.clear_cookies(secure)) if e.code == "invalid_grant"

        return Reply.json(e.status && e.status < 500 ? 400 : 502, { "error" => e.code })
      end
      Reply.json(200, { "user" => User.from_claims(renewed[:claims]).to_h }, @client.session_cookies(tokens, secure))
    end

    # The person's own teams, through the app's server (InID checks what their team role lets
    # them do): teams, teams/{id}, teams/{id}/members… → /v1/users/{sub}/teams…
    def teams(env, method, action)
      current = @client.read_session(env["HTTP_COOKIE"], secure: @client.secure?(env)).session
      return Reply.json(401, { "error" => "not_signed_in" }) unless current

      rest = action.delete_prefix("teams")
      unless rest.match?(TEAMS_REST) && %w[GET POST PATCH DELETE].include?(method)
        return Reply.json(404, { "error" => "not_found" })
      end

      body = %w[POST PATCH].include?(method) ? body_of(env, 1024 * 1024) : ""
      res = @client.app_request(method, "/v1/users/#{Util.escape(current.user.id)}/teams#{rest}", body.empty? ? nil : body)
      answer = begin
        JSON.parse(res.body.to_s)
      rescue JSON::ParserError
        { "error" => "teams_unavailable" }
      end
      Reply.json(res.status >= 500 ? 502 : res.status, answer)
    end

    # The person's sessions at this app; DELETE sessions/{id} ends one, sessions?others=1 all
    # but this one
    def sessions(env, method, action, query)
      current = @client.read_session(env["HTTP_COOKIE"], secure: @client.secure?(env)).session
      return Reply.json(401, { "error" => "not_signed_in" }) unless current

      base = "/v1/users/#{Util.escape(current.user.id)}/sessions"
      sid = current.claims["sid"].is_a?(String) ? current.claims["sid"] : nil
      list = -> { Array(@client.app_api("GET", base)["sessions"]) }
      case method
      when "GET"
        Reply.json(200, { "sessions" => list.call.map { |s| s.merge("current" => s["id"] == sid) } })
      when "DELETE"
        ending = if action.start_with?("sessions/") then [Util.unescape(action.delete_prefix("sessions/"))]
                 elsif query["others"] && !query["others"].empty? then list.call.map { |s| s["id"] }.reject { |id| id == sid }
                 else []
                 end
        ending.each do |id|
          @client.app_api("DELETE", "#{base}/#{Util.escape(id)}")
        rescue APIError
          nil
        end
        Reply.json(200, { "ended" => ending.length })
      else
        Reply.json(404, { "error" => "not_found" })
      end
    rescue APIError
      Reply.json(502, { "error" => "sessions_unavailable" })
    end
  end
end
