# frozen_string_literal: true

# Verifies the committed clean-room method-94 research corpus without invoking
# either external fixture tool.

require "base64"
require "digest"
require "json"
require "set"

def decode(path)
  Base64.strict_decode64(File.read(path).gsub(/\s+/, ""))
end

def check(condition, message)
  raise message unless condition
end

root = File.expand_path(ARGV.fetch(0, File.join(__dir__, "research")))
manifest = JSON.parse(File.read(File.join(root, "manifest.json")))
check(manifest.fetch("schema") == 1, "unsupported manifest schema")
check(
  manifest.dig("packmp3_source", "sha256") == manifest.dig("packmp3_binary", "sha256"),
  "packMP3 source record and oracle binary hash differ"
)

expected_files = Set.new
mp3_hashes = Set.new
pmp_hashes = Set.new
total_mp3 = 0
total_pmp = 0

manifest.fetch("cases").each do |entry|
  name = entry.fetch("name")
  check(entry.fetch("accepted"), "unaccepted case is committed: #{name}")
  check(entry.fetch("round_trip"), "case lacks a byte-exact oracle round trip: #{name}")
  check(entry.fetch("packmp3_exit").zero?, "packMP3 returned an error for #{name}")
  check(entry["packmp3_diagnostic"].nil?, "packMP3 recorded an error for #{name}")

  mp3_name = "#{name}.mp3.b64"
  pmp_name = "#{name}.pmp.b64"
  expected_files.add(mp3_name)
  expected_files.add(pmp_name)
  mp3 = decode(File.join(root, "pairs", mp3_name))
  pmp = decode(File.join(root, "pairs", pmp_name))

  mp3_record = entry.fetch("mp3")
  pmp_record = entry.fetch("pmp")
  check(mp3.bytesize == mp3_record.fetch("bytes"), "MP3 size mismatch for #{name}")
  check(pmp.bytesize == pmp_record.fetch("bytes"), "PMP size mismatch for #{name}")
  check(Digest::SHA256.hexdigest(mp3) == mp3_record.fetch("sha256"), "MP3 hash mismatch for #{name}")
  check(Digest::SHA256.hexdigest(pmp) == pmp_record.fetch("sha256"), "PMP hash mismatch for #{name}")
  check(mp3.start_with?("ID3") || mp3.getbyte(0) == 0xff, "MP3 signature mismatch for #{name}")
  check(pmp.start_with?("MS\x0a".b), "PMP v1.0 signature mismatch for #{name}")

  mp3_hashes.add(mp3_record.fetch("sha256"))
  pmp_hashes.add(pmp_record.fetch("sha256"))
  total_mp3 += mp3.bytesize
  total_pmp += pmp.bytesize
end

actual_files = Dir.children(File.join(root, "pairs")).to_set
check(actual_files == expected_files, "pair directory does not exactly match the manifest")

puts [
  "verified #{manifest.fetch('cases').length} method-94 pairs",
  "#{mp3_hashes.length} unique MP3 streams",
  "#{pmp_hashes.length} unique PMP streams",
  "#{total_mp3} MP3 bytes",
  "#{total_pmp} PMP bytes"
].join(", ")
