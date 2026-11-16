# frozen_string_literal: true

require "net/http"
require "uri"

module InID
  # What a transport answers
  Response = Struct.new(:status, :body) do
    def ok? = status.between?(200, 299)

    def json
      JSON.parse(body.to_s)
    rescue JSON::ParserError
      {}
    end
  end

  # Calls to InID over Net::HTTP. Any object with the same #call works (tests pass a fake).
  class NetHTTPTransport
    def call(method, url, headers: {}, body: nil, timeout: 10)
      uri = URI(url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == "https"
      http.open_timeout = timeout
      http.read_timeout = timeout
      request = Net::HTTPGenericRequest.new(method, !body.nil?, true, uri.request_uri, headers)
      request.body = body if body
      res = http.request(request)
      Response.new(res.code.to_i, res.body)
    rescue StandardError => e
      # Unreachable (DNS, refused, timeout, TLS): callers keep what is still valid
      raise NetworkError, e.message
    end
  end
end
