# Independent native resolver evidence, kept separate from the plugin's SBOM.
require 'json'
require 'bundler'
require 'rubygems/package'

project = Gem::Package.new(Dir['/reference/*.gem'].first).spec
specs = Bundler.load.specs.to_a
by_name = specs.to_h { |spec| [spec.name, spec] }
identity = ->(spec) { "pkg:gem/#{spec.name}@#{spec.version}" }
edges = specs.map do |spec|
  deps = spec.runtime_dependencies.map do |dep|
    selected = by_name.fetch(dep.name)
    raise "unsatisfied #{dep.name}" unless dep.requirement.satisfied_by?(selected.version)
    identity.call(selected)
  end
  {ref: identity.call(spec), dependsOn: deps.sort}
end
root = identity.call(project)
raise 'project missing from resolved bundle' unless edges.any? { |edge| edge[:ref] == root }
by_ref = edges.to_h { |edge| [edge[:ref], edge] }
reachable = []
pending = [root]
until pending.empty?
  ref = pending.shift
  next if reachable.include?(ref)
  reachable << ref
  pending.concat(by_ref.fetch(ref)[:dependsOn])
end
edges.select! { |edge| reachable.include?(edge[:ref]) }
File.write('/reference/native-graph.json', JSON.pretty_generate({
  source: 'Gem::Package built gemspec + Bundler.load.specs',
  scope: 'runtime dependencies of packaged gem; development dependencies excluded',
  root: root, dependencies: edges, ruby_version: RUBY_VERSION, bundler_version: Bundler::VERSION
}) + "\n")
