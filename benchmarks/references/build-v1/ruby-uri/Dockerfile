FROM ruby:3.3-bookworm AS build
RUN git clone https://github.com/CycloneDX/cyclonedx-ruby-gem.git /generator && cd /generator && git checkout 7efedd6422cc32d9bdefbb6eddb7b4eaa3857309 && gem build cyclonedx-ruby.gemspec && gem install --no-document *.gem
WORKDIR /src
COPY src/ /src/
RUN gem build *.gemspec && mkdir /reference && cp *.gem /reference/ && gem install --no-document /reference/*.gem
RUN mkdir /resolution && printf 'source "https://rubygems.org"\n' > /resolution/Gemfile && ruby -e 's=Gem::Package.new(Dir["/reference/*.gem"].first).spec; File.open("/resolution/Gemfile", "a") { |f| f.puts "gem #{s.name.inspect}, path: \"/src\"" }' -rrubygems/package
RUN cd /resolution && bundle lock && bundle install && cyclonedx-ruby -p /resolution -f json -s 1.6 -o /reference/sbom.json && cp Gemfile Gemfile.lock /reference/
COPY ruby_reference_graph.rb /native-graph.rb
RUN cd /resolution && ruby /native-graph.rb
FROM scratch AS export
COPY --from=build /reference/ /
