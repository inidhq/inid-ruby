# frozen_string_literal: true

require_relative "lib/inid/version"

Gem::Specification.new do |spec|
  spec.name = "inid"
  spec.version = InID::VERSION
  spec.authors = ["InID"]
  spec.summary = "Sign-in with InID for Ruby: Rack middleware, Rails helpers, webhooks and the app API"
  spec.description = "Passwordless sign-in with InID (phone code, passkeys, Google) for Rack, Sinatra and Rails apps. " \
                     "Standard library only."
  spec.homepage = "https://inid.co"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.1"
  spec.files = Dir["lib/**/*.rb", "README.md", "LICENSE"]
  spec.require_paths = ["lib"]
  spec.metadata["rubygems_mfa_required"] = "true"
end
