# InID for Ruby

Sign-in with [InID](https://inid.co) for Rack, Sinatra and Rails. People sign in with their phone (a code by WhatsApp or SMS), Face ID, their fingerprint or Google, without passwords; your server knows who they are, their role and their permissions.

Ruby 3.1+, standard library only. Rails is optional.

```ruby
# Gemfile
gem "inid"
```

Set your keys from InID's panel (Settings → Keys):

```bash
INID_PUBLISHABLE_KEY=pk_test_...
INID_SECRET_KEY=sk_test_...
INID_WEBHOOK_SECRET=whsec_...          # only to verify webhooks
INID_APP_URL=https://app.example.com   # behind a proxy that hides the scheme or host
```

## Rack and Sinatra

```ruby
require "sinatra"
require "inid"

use InID::Middleware, protect: [
  "/dashboard",                                        # signed in (and its subpaths)
  { path: "/admin", role: "admin" },                   # signed in with a role
  { path: "/team", entrance: "team" },                 # through an entrance
  %r{\A/reports/\d+\z}                                 # a pattern
]

get "/dashboard" do
  auth = env["inid"]
  "Hola, #{auth.user.name}"
end
```

The middleware answers InID's routes under `/api/inid` (sign in, callback, sign out, session, sessions), renews the session before it ends, sends whoever isn't signed in from a protected path to sign in (and back), and answers `403` to someone signed in without the role or permission a rule asks for.

`env["inid"]` is an `InID::Auth`: `signed_in?`, `user_id`, `user` (`id`, `first_name`, `last_name`, `name`, `email`, `email_verified?`, `phone`, `roles`, `permissions`, `public_metadata`), `session` (with the token's `claims`) and `has?(role: "admin")` / `has?(permission: "invoices:read")`.

Options: `protect:` (strings, regexps, hashes, or a proc taking the env), `routes: false` to leave `/api/inid` to your app (mount `InID.client` there, it's a Rack app), `client:` for a configured `InID::Client`, or the client's own options (`publishable_key:`, `secret_key:`, `issuer:`, `app_url:`, `api_path:`, `scope:`).

## Rails

With `INID_PUBLISHABLE_KEY` set (or `config.inid.publishable_key`), the Railtie inserts the middleware. Protect paths in `config/application.rb`:

```ruby
config.inid.protect = ["/dashboard", { path: "/admin", role: "admin" }]
```

In controllers:

```ruby
class AdminController < ApplicationController
  require_inid! role: "admin"                 # a before_action; takes only:/except:

  def index
    @user = inid_user                         # also inid_signed_in?, inid_auth
  end
end
```

`require_inid!` sends whoever isn't signed in to sign in and answers `403` without the role or permission. In views, the sign-in form (a web component from [`@inid/js`](https://www.npmjs.com/package/@inid/js)):

```erb
<%= inid_sign_in(app_name: "Mi App") %>
```

It renders the `@inid/js` script and `<inid-sign-in app-name="Mi App">`; pass `script: false` if the page already loads it (`inid_script_tag`).

## Native apps

An iOS or Android app sends its ID token to your backend as `Authorization: Bearer <id_token>`:

```ruby
session = InID.verify_bearer(request.headers["Authorization"])
halt 401 unless session
session.user.id
```

## Webhooks

Pass the raw body, as received:

```ruby
post "/webhooks/inid" do
  event = InID.verify_webhook(request.body.read, request.env["HTTP_INID_SIGNATURE"])
  case event["type"]
  when "user.deleted" then User.where(inid_id: event["sub"]).destroy_all
  when "session.ended" then # event["sub"], event["sid"]
  end
  200
rescue InID::InvalidSignature
  400
end
```

## The app API

With your secret key:

```ruby
client = InID.client                                    # from the environment
client.get_user(sub)
client.set_role(sub, "admin")                           # nil for the default role
client.set_metadata(sub, public_metadata: { plan: "pro" }, private_metadata: { stripe: "cus_..." })
client.roles
client.invite(email: "ana@example.com", role: "staff")  # or invite([{ email:, role: }, ...])
```

Errors from InID raise `InID::APIError` with `code` (`user_not_found`, `unknown_role`…) and `status`; when InID can't be reached, `InID::NetworkError`.

## Development

```bash
bundle install && bundle exec rake test
```

## License

MIT
