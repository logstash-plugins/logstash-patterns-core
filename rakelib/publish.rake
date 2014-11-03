require "gem_publisher"

desc "Publish gem to RubyGems.org"
task :publish_gem do |t|
  gem_file = Dir.glob(File.expand_path('../*.gemspec',File.dirname(__FILE__))).first
  gem = GemPublisher.publish_if_updated(gem_file, :rubygems)
  puts "Published #{gem}" if gem
end

