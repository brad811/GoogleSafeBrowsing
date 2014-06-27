Gem::Specification.new do |s|
  s.name               = "google_safe_browsing_redis"
  s.version            = "0.0.6"
  s.default_executable = "google_safe_browsing_redis"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Brad Jewell"]
  s.date = %q{2014-06-27}
  s.description = %q{A ruby implementation of the Google Safe Browsing API v2 that uses Redis}
  s.email = %q{brad811@gmail.com}
  s.files = ["lib/canonicalize.rb", "lib/google_safe_browsing.rb"]
  s.homepage = %q{https://github.com/brad811/GoogleSafeBrowsing}
  s.require_paths = ["lib"]
  s.rubygems_version = %q{1.6.2}
  s.summary = %q{A ruby implementation of the Google Safe Browsing API v2 that uses Redis}

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
    else
    end
  else
  end
end
