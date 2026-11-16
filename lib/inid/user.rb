# frozen_string_literal: true

module InID
  # The signed-in person, from the ID token. to_h / to_json use the camelCase names the
  # browser components expect.
  class User
    attr_reader :id, :first_name, :last_name, :name, :email, :phone, :roles, :permissions, :public_metadata

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
        public_metadata: meta.is_a?(Hash) ? meta : {}
      )
    end

    def initialize(id:, first_name: nil, last_name: nil, name: nil, email: nil, email_verified: false, phone: nil,
                   roles: [], permissions: [], public_metadata: {})
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
    end

    def email_verified? = @email_verified

    # has?(role: "admin"), has?(permission: "invoices:read"); both must hold. With neither,
    # true: a protect rule with only a path lets anyone signed in through
    def has?(role: nil, permission: nil)
      return false if role && !roles.include?(role.to_s)
      return false if permission && !permissions.include?(permission.to_s)

      true
    end

    def to_h
      {
        "id" => id, "firstName" => first_name, "lastName" => last_name, "name" => name, "email" => email,
        "emailVerified" => email_verified?, "phone" => phone, "roles" => roles, "permissions" => permissions,
        "publicMetadata" => public_metadata
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

    def has?(role: nil, permission: nil)
      user ? user.has?(role: role, permission: permission) : false
    end
  end
end
