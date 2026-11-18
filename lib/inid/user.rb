# frozen_string_literal: true

module InID
  # The person's active team (apps with teams), chosen per session: their role there and what
  # it allows
  class Team
    attr_reader :id, :slug, :name, :role, :permissions

    # The ID token's team claim; nil when it's missing or malformed
    def self.from_claim(claim)
      return nil unless claim.is_a?(Hash) && claim["id"].is_a?(String) && claim["role"].is_a?(String)

      new(id: claim["id"], slug: claim["slug"].is_a?(String) ? claim["slug"] : "",
          name: claim["name"].is_a?(String) ? claim["name"] : "", role: claim["role"],
          permissions: claim["permissions"].is_a?(Array) ? claim["permissions"].grep(String) : [])
    end

    def initialize(id:, role:, slug: "", name: "", permissions: [])
      @id = id
      @slug = slug
      @name = name
      @role = role
      @permissions = permissions
    end

    def to_h = { "id" => id, "slug" => slug, "name" => name, "role" => role, "permissions" => permissions }
    def to_json(*args) = to_h.to_json(*args)

    def ==(other)
      other.is_a?(Team) && to_h == other.to_h
    end
  end

  # The signed-in person, from the ID token. to_h / to_json use the camelCase names the
  # browser components expect.
  class User
    # team: the team they're working in now (apps with teams), with their role there; nil: none
    attr_reader :id, :first_name, :last_name, :name, :email, :phone, :roles, :permissions, :public_metadata, :team

    def self.from_claims(claims)
      text = ->(v) { v.is_a?(String) && !v.empty? ? v : nil }
      strings = ->(v) { v.is_a?(Array) ? v.grep(String) : [] }
      first = text.(claims["given_name"])
      last = text.(claims["family_name"])
      full = [first, last].compact.join(" ")
      meta = claims["public_metadata"]
      new(
        id: claims["sub"].to_s,
        first_name: first,
        last_name: last,
        name: full.empty? ? text.(claims["name"]) : full,
        email: text.(claims["email"]),
        email_verified: claims["email_verified"] == true,
        phone: text.(claims["phone_number"]),
        roles: strings.(claims["roles"]),
        permissions: strings.(claims["permissions"]),
        public_metadata: meta.is_a?(Hash) ? meta : {},
        team: Team.from_claim(claims["team"])
      )
    end

    def initialize(id:, first_name: nil, last_name: nil, name: nil, email: nil, email_verified: false, phone: nil,
                   roles: [], permissions: [], public_metadata: {}, team: nil)
      @id = id
      @first_name = first_name
      @last_name = last_name
      @name = name
      @email = email
      @email_verified = email_verified
      @phone = phone
      @roles = roles
      @permissions = permissions
      @public_metadata = public_metadata
      @team = team
    end

    def email_verified? = @email_verified

    # has?(role: "admin"), has?(permission: "invoices:read"), has?(team_role: "admin"); every
    # one given must hold. With none, true: a protect rule with only a path lets anyone signed
    # in through. A permission counts from their app role or their active team's role.
    def has?(role: nil, permission: nil, team_role: nil)
      return false if role && !roles.include?(role.to_s)
      return false if team_role && team&.role != team_role.to_s
      return false if permission && !permissions.include?(permission.to_s) && !team&.permissions&.include?(permission.to_s)

      true
    end

    def to_h
      {
        "id" => id, "firstName" => first_name, "lastName" => last_name, "name" => name, "email" => email,
        "emailVerified" => email_verified?, "phone" => phone, "roles" => roles, "permissions" => permissions,
        "publicMetadata" => public_metadata, "team" => team&.to_h
      }
    end

    def to_json(*args) = to_h.to_json(*args)
  end

  # A verified sign-in: the user, when its token ends (seconds since 1970) and the token's claims
  Session = Struct.new(:user, :expires_at, :claims, keyword_init: true)

  # Who is signed in, for a request (env["inid"] under the middleware)
  class Auth
    attr_reader :session

    def initialize(session = nil)
      @session = session
    end

    def signed_in? = !session.nil?
    def user = session&.user
    def user_id = session&.user&.id

    def has?(role: nil, permission: nil, team_role: nil)
      user ? user.has?(role: role, permission: permission, team_role: team_role) : false
    end
  end
end
