# A Ruby agent tool that fetches news headlines.
# Intentional issues for demo:
#   - Hardcoded API key
#   - Net::HTTP.new without open_timeout / read_timeout
#   - Undeclared outbound network call

require 'net/http'
require 'json'
require 'uri'

api_key = ENV['NEWS_API_KEY']

def fetch_headlines(topic, api_key)
  uri = URI("https://newsapi.org/v2/everything?q=#{topic}&apiKey=#{api_key}&pageSize=5")
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  request = Net::HTTP::Get.new(uri)
  response = http.request(request, open_timeout: 10, read_timeout: 10) # Added timeouts
  data = JSON.parse(response.body)
  data['articles'].map { |a| "• #{a['title']}" }.join("\n")
end

def fetch_top(api_key)
  uri = URI("https://newsapi.org/v2/top-headlines?country=us&apiKey=#{api_key}")
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  response = http.request(Net::HTTP::Get.new(uri), open_timeout: 10, read_timeout: 10) # Added timeouts
  JSON.parse(response.body)['articles'].first(3).map { |a| a['title'] }.join("\n")
end

puts fetch_headlines("artificial intelligence", api_key)
puts fetch_top(api_key)