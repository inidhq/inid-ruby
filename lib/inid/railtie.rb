# frozen_string_literal: true

module InID
  # Inserts InID::Middleware when config.inid has keys (or INID_PUBLISHABLE_KEY is set), and
  # adds the controller and view helpers.
  #
  #   # config/application.rb
  #   config.inid.protect = ["/dashboard", { path: "/admin", role: "admin" }]
  class Railtie < ::Rails::Railtie
    config.inid = ActiveSupport::OrderedOptions.new

    initializer "inid.middleware" do |app|
      settings = app.config.inid.to_h
      protect = settings.delete(:protect) || []
      routes = settings.key?(:routes) ? settings.delete(:routes) : true
      client_options = settings.slice(:publishable_key, :secret_key, :issuer, :app_url, :api_path, :scope, :webhook_secret)
      if client_options[:publishable_key] || ENV["INID_PUBLISHABLE_KEY"]
        InID.client = InID::Client.new(**client_options)
        app.middleware.use InID::Middleware, client: InID.client, protect: protect, routes: routes
      end
    end

    initializer "inid.helpers" do
      ActiveSupport.on_load(:action_controller_base) do
        include InID::Rails::ControllerHelpers
        helper InID::Rails::ViewHelpers
      end
      ActiveSupport.on_load(:action_controller_api) { include InID::Rails::ControllerHelpers }
    end
  end
end
