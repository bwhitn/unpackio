# frozen_string_literal: true

# Generates deterministic project-authored MPEG-1 Layer III inputs and PMP
# oracle outputs for clean-room ZIP method-94 research.
#
# LAME and packMP3 are external fixture tools only. They are never linked,
# shipped, or invoked by unpackio. The generated manifest records their exact
# byte identities and every argument used. packMP3 source must not be inspected
# or adapted while using this workflow.

require "base64"
require "digest"
require "fileutils"
require "json"
require "open3"

LAME_SOURCE = {
  "url" => "https://downloads.sourceforge.net/project/lame/lame/4.0/lame-4.0.tar.gz",
  "sha256" => "3df5124d5ad3a98312ffd7ba6a9b36230e4f8a3e66d3ce0f425e336c32d216eb",
  "license" => "LGPL-2.0-or-later; external fixture generator only"
}.freeze

PACKMP3_SOURCE = {
  "repository" => "https://github.com/packjpg/packMP3",
  "revision" => "e61c11941552f4ffe6e219a847f441d9520d2e50",
  "sha256" => "09a51dd32c8c9940409769c5f32219ce704941a9531fa26182363cca6a8cb429",
  "license" => "LGPL-3.0-or-later; external oracle only"
}.freeze

def chunk(id, payload)
  raise "chunk id must contain four bytes" unless id.bytesize == 4

  id + [payload.bytesize].pack("V") + payload + (payload.bytesize.odd? ? "\0" : "")
end

def wave(channels, rate, samples)
  align = channels * 2
  format = [1, channels, rate, rate * align, align, 16].pack("vvVVvv")
  body = "WAVE" + chunk("fmt ", format) + chunk("data", samples.pack("s<*"))
  "RIFF" + [body.bytesize].pack("V") + body
end

def clamp16(value)
  [[value, -32_768].max, 32_767].min
end

def triangle(index, period, amplitude)
  phase = index % period
  half = period / 2
  scaled = phase < half ? phase : period - phase
  ((scaled * amplitude * 2) / half) - amplitude
end

def xorshift32(value)
  value ^= (value << 13) & 0xffff_ffff
  value ^= value >> 17
  value ^ ((value << 5) & 0xffff_ffff)
end

def pcm(profile, rate, channels, frames)
  state = 0x94c0_de01
  Array.new(frames * channels) do |flat_index|
    frame = flat_index / channels
    channel = flat_index % channels
    case profile
    when "silence"
      0
    when "impulse"
      (frame % 4096).zero? ? (channel.zero? ? 28_000 : -28_000) : 0
    when "tones"
      first = triangle(frame, [rate / 440, 8].max, 12_000)
      second = triangle(frame, [rate / 997, 8].max, 4_000)
      clamp16(first + (channel.zero? ? second : -second))
    when "noise"
      state = xorshift32(state)
      ((state >> 16) & 0xffff) - 32_768
    when "transient"
      if (frame / 1152).even?
        0
      else
        state = xorshift32(state)
        ((((state >> 16) & 0xffff) - 32_768) * 3) / 4
      end
    when "stereo_correlated"
      triangle(frame, [rate / 523, 8].max, channel.zero? ? 15_000 : 14_000)
    when "stereo_antiphase"
      value = triangle(frame, [rate / 659, 8].max, 15_000)
      channel.zero? ? value : -value
    when "stereo_split"
      triangle(frame, [rate / (channel.zero? ? 330 : 880), 8].max, 15_000)
    else
      raise "unknown PCM profile #{profile.inspect}"
    end
  end
end

def sha256(path)
  Digest::SHA256.file(path).hexdigest
end

def encode_base64(path, destination)
  encoded = Base64.strict_encode64(File.binread(path)).scan(/.{1,76}/).join("\n") + "\n"
  File.write(destination, encoded)
end

def run(*arguments)
  stdout, stderr, status = Open3.capture3(*arguments)
  [status.exitstatus, stdout, stderr]
end

def tool_identity(path, version_arguments, allow_nonzero: false)
  status, stdout, stderr = run(path, *version_arguments)
  raise "failed to identify #{path}" unless status.zero? || allow_nonzero

  {
    "path_basename" => File.basename(path),
    "sha256" => sha256(path),
    "version" => (stdout + stderr).lines.map(&:strip).find { |line| !line.empty? }
  }
end

def case_definition(name, profile:, rate: 44_100, channels: 1, frames: nil, arguments: [])
  {
    "name" => name,
    "profile" => profile,
    "rate" => rate,
    "channels" => channels,
    "frames" => frames || rate,
    "arguments" => arguments
  }
end

def synthetic_case_definition(name, mode_extension:)
  {
    "name" => name,
    "synthetic_mp3" => {
      "profile" => "zero-main-data MPEG-1 Layer III",
      "sample_rate" => 44_100,
      "sample_rate_index" => 0,
      "bitrate_kbps" => 128,
      "bitrate_index" => 9,
      "channel_mode" => 1,
      "mode_extension" => mode_extension,
      "frames" => 5
    }
  }
end

def synthetic_mp3(definition)
  sample_rate = definition.fetch("sample_rate")
  bitrate = definition.fetch("bitrate_kbps")
  header = 0xffe0_0000
  header |= 0x3 << 19 # MPEG-1
  header |= 0x1 << 17 # Layer III
  header |= 0x1 << 16 # no CRC
  header |= definition.fetch("bitrate_index") << 12
  header |= definition.fetch("sample_rate_index") << 10
  header |= definition.fetch("channel_mode") << 6
  header |= definition.fetch("mode_extension") << 4
  header |= 0x1 << 2 # original
  frame_size = (144_000 * bitrate) / sample_rate
  raise "synthetic MPEG frame is too small" if frame_size < 36

  frame = [header].pack("N") + ("\0" * (frame_size - 4))
  frame * definition.fetch("frames")
end

cases = [
  case_definition("baseline_mono_44100_128", profile: "tones", arguments: %w[--cbr -b 128 -m m]),
  case_definition("mono_44100_032", profile: "tones", arguments: %w[--cbr -b 32 -m m]),
  case_definition("mono_44100_040", profile: "tones", arguments: %w[--cbr -b 40 -m m]),
  case_definition("mono_44100_048", profile: "tones", arguments: %w[--cbr -b 48 -m m]),
  case_definition("mono_44100_056", profile: "tones", arguments: %w[--cbr -b 56 -m m]),
  case_definition("mono_44100_064", profile: "tones", arguments: %w[--cbr -b 64 -m m]),
  case_definition("mono_44100_080", profile: "tones", arguments: %w[--cbr -b 80 -m m]),
  case_definition("mono_44100_096", profile: "tones", arguments: %w[--cbr -b 96 -m m]),
  case_definition("mono_44100_112", profile: "tones", arguments: %w[--cbr -b 112 -m m]),
  case_definition("mono_44100_192", profile: "tones", arguments: %w[--cbr -b 192 -m m]),
  case_definition("mono_44100_160", profile: "tones", arguments: %w[--cbr -b 160 -m m]),
  case_definition("mono_44100_224", profile: "tones", arguments: %w[--cbr -b 224 -m m]),
  case_definition("mono_44100_256", profile: "tones", arguments: %w[--cbr -b 256 -m m]),
  case_definition("mono_44100_320", profile: "tones", arguments: %w[--cbr -b 320 -m m]),
  case_definition("mono_32000_128", profile: "tones", rate: 32_000, arguments: %w[--cbr -b 128 -m m]),
  case_definition("mono_48000_128", profile: "tones", rate: 48_000, arguments: %w[--cbr -b 128 -m m]),
  case_definition("mono_silence", profile: "silence", arguments: %w[--cbr -b 128 -m m]),
  case_definition("mono_impulse", profile: "impulse", arguments: %w[--cbr -b 128 -m m]),
  case_definition("mono_noise", profile: "noise", arguments: %w[--cbr -b 128 -m m]),
  case_definition("mono_transient", profile: "transient", arguments: %w[--cbr -b 128 -m m]),
  case_definition("mono_short", profile: "tones", frames: 11_025, arguments: %w[--cbr -b 128 -m m]),
  case_definition("mono_long", profile: "tones", frames: 88_200, arguments: %w[--cbr -b 128 -m m]),
  case_definition("mono_crc", profile: "tones", arguments: %w[--cbr -b 128 -m m -p]),
  case_definition("mono_no_reservoir", profile: "tones", arguments: %w[--cbr -b 128 -m m --nores]),
  case_definition("mono_copyright", profile: "tones", arguments: %w[--cbr -b 128 -m m -c]),
  case_definition("mono_non_original", profile: "tones", arguments: %w[--cbr -b 128 -m m -o]),
  case_definition("mono_emphasis_50_15", profile: "tones", arguments: %w[--cbr -b 128 -m m -e 5]),
  case_definition("mono_id3v1", profile: "tones", arguments: ["--cbr", "-b", "128", "-m", "m", "--id3v1-only", "--tt", "unpackio-method94", "--ta", "project-authored"]),
  case_definition("mono_id3v2", profile: "tones", arguments: ["--cbr", "-b", "128", "-m", "m", "--id3v2-only", "--pad-id3v2-size", "256", "--tt", "unpackio method 94 clean room corpus"]),
  case_definition("stereo_joint", profile: "stereo_split", channels: 2, arguments: %w[--cbr -b 128 -m j]),
  case_definition("stereo_simple", profile: "stereo_split", channels: 2, arguments: %w[--cbr -b 128 -m s]),
  case_definition("stereo_force_ms", profile: "stereo_correlated", channels: 2, arguments: %w[--cbr -b 128 -m f]),
  case_definition("stereo_dual", profile: "stereo_split", channels: 2, arguments: %w[--cbr -b 128 -m d]),
  case_definition("stereo_antiphase", profile: "stereo_antiphase", channels: 2, arguments: %w[--cbr -b 192 -m j]),
  case_definition("stereo_32000_128", profile: "stereo_split", rate: 32_000, channels: 2, arguments: %w[--cbr -b 128 -m j]),
  case_definition("stereo_48000_128", profile: "stereo_split", rate: 48_000, channels: 2, arguments: %w[--cbr -b 128 -m j]),
  case_definition("stereo_064", profile: "stereo_split", channels: 2, arguments: %w[--cbr -b 64 -m j]),
  case_definition("stereo_096", profile: "stereo_split", channels: 2, arguments: %w[--cbr -b 96 -m j]),
  case_definition("stereo_160", profile: "stereo_split", channels: 2, arguments: %w[--cbr -b 160 -m j]),
  case_definition("stereo_224", profile: "stereo_split", channels: 2, arguments: %w[--cbr -b 224 -m j]),
  case_definition("stereo_256", profile: "stereo_split", channels: 2, arguments: %w[--cbr -b 256 -m j]),
  case_definition("stereo_320", profile: "stereo_split", channels: 2, arguments: %w[--cbr -b 320 -m j]),
  case_definition("stereo_crc", profile: "stereo_split", channels: 2, arguments: %w[--cbr -b 192 -m j -p]),
  case_definition("stereo_no_reservoir", profile: "stereo_split", channels: 2, arguments: %w[--cbr -b 192 -m j --nores]),
  case_definition("mono_abr_096", profile: "tones", arguments: %w[--abr 96 -m m]),
  case_definition("stereo_abr_192", profile: "stereo_split", channels: 2, arguments: %w[--abr 192 -m j]),
  case_definition("mono_vbr_0", profile: "tones", arguments: %w[-V 0 -m m]),
  case_definition("mono_vbr_4", profile: "tones", arguments: %w[-V 4 -m m]),
  case_definition("mono_vbr_9", profile: "tones", arguments: %w[-V 9 -m m]),
  case_definition("mono_cbr_no_tag", profile: "tones", arguments: %w[--cbr -b 128 -m m -t]),
  case_definition("mono_vbr_no_tag", profile: "tones", arguments: %w[-V 4 -m m -t]),
  case_definition("stereo_vbr_2", profile: "stereo_split", channels: 2, arguments: %w[-V 2 -m j]),
  case_definition("stereo_vbr_no_tag", profile: "stereo_split", channels: 2, arguments: %w[-V 2 -m j -t]),
  synthetic_case_definition("stereo_intensity", mode_extension: 1)
].freeze

root = File.expand_path(ARGV.fetch(0))
lame = File.expand_path(ENV.fetch("LAME_ENCODER"))
packmp3 = File.expand_path(ENV.fetch("PACKMP3_ORACLE"))
emit_base64 = ENV.fetch("EMIT_BASE64", "0") == "1"

if Dir.exist?(root)
  raise "output directory must be empty" unless Dir.empty?(root)
else
  FileUtils.mkdir_p(root)
end
work = File.join(root, "work")
pairs = File.join(root, "pairs")
FileUtils.mkdir_p(work)
FileUtils.mkdir_p(pairs) if emit_base64

lame_identity = tool_identity(lame, ["--version"])
packmp3_identity = tool_identity(packmp3, ["-np"], allow_nonzero: true)
unless packmp3_identity.fetch("sha256") == PACKMP3_SOURCE.fetch("sha256")
  raise "packMP3 oracle hash does not match the pinned binary"
end

results = cases.map do |definition|
  name = definition.fetch("name")
  case_root = File.join(work, name)
  decode_root = File.join(case_root, "decode")
  FileUtils.mkdir_p(decode_root)
  wav_path = File.join(case_root, "#{name}.wav")
  mp3_path = File.join(case_root, "#{name}.mp3")
  pmp_path = File.join(case_root, "#{name}.pmp")

  synthetic_definition = definition["synthetic_mp3"]
  if synthetic_definition
    File.binwrite(mp3_path, synthetic_mp3(synthetic_definition))
    source_record = { "synthetic_mp3" => synthetic_definition }
  else
    samples = pcm(
      definition.fetch("profile"),
      definition.fetch("rate"),
      definition.fetch("channels"),
      definition.fetch("frames")
    )
    File.binwrite(wav_path, wave(definition.fetch("channels"), definition.fetch("rate"), samples))

    rate_khz = format("%g", definition.fetch("rate") / 1000.0)
    recorded_lame_arguments = [
      "-S", "--noreplaygain", "-q", "2", "--resample", rate_khz,
      *definition.fetch("arguments")
    ]
    lame_arguments = [*recorded_lame_arguments, wav_path, mp3_path]
    lame_status, = run(lame, *lame_arguments)
    raise "LAME failed for #{name}" unless lame_status.zero? && File.file?(mp3_path)
    source_record = {
      "pcm" => definition.slice("profile", "rate", "channels", "frames"),
      "lame_arguments" => recorded_lame_arguments,
      "wav" => { "bytes" => File.size(wav_path), "sha256" => sha256(wav_path) }
    }
  end

  oracle_arguments = ["-ver", "-v2", "-np", "-o", mp3_path]
  oracle_status, oracle_stdout, oracle_stderr = run(packmp3, *oracle_arguments)
  accepted = oracle_status.zero? && File.file?(pmp_path)
  oracle_diagnostic = (oracle_stdout + oracle_stderr)[/fatal error:\s*\n\s*([^\n]+)/, 1]&.strip

  result = { "name" => name }.merge(source_record).merge(
    "mp3" => { "bytes" => File.size(mp3_path), "sha256" => sha256(mp3_path) },
    "packmp3_exit" => oracle_status,
    "packmp3_diagnostic" => oracle_diagnostic,
    "accepted" => accepted
  )
  next result unless accepted

  decoded_pmp = File.join(decode_root, "#{name}.pmp")
  FileUtils.cp(pmp_path, decoded_pmp)
  decode_status, = run(packmp3, "-v2", "-np", "-o", decoded_pmp)
  decoded_mp3 = File.join(decode_root, "#{name}.mp3")
  round_trip = decode_status.zero? && File.file?(decoded_mp3) && File.binread(decoded_mp3) == File.binread(mp3_path)
  raise "packMP3 round trip failed for #{name}" unless round_trip

  result["pmp"] = { "bytes" => File.size(pmp_path), "sha256" => sha256(pmp_path) }
  result["round_trip"] = true

  if emit_base64
    encode_base64(mp3_path, File.join(pairs, "#{name}.mp3.b64"))
    encode_base64(pmp_path, File.join(pairs, "#{name}.pmp.b64"))
  end
  result
end

manifest = {
  "schema" => 1,
  "purpose" => "clean-room ZIP method-94/PMP format research",
  "source_media" => "deterministic project-authored integer PCM waveforms plus a standards-based synthetic MPEG-1 Layer III stream; MIT",
  "lame_source" => LAME_SOURCE,
  "lame_binary" => lame_identity,
  "packmp3_source" => PACKMP3_SOURCE,
  "packmp3_binary" => packmp3_identity,
  "cases" => results
}
File.write(File.join(root, "manifest.json"), JSON.pretty_generate(manifest) + "\n")

accepted_count = results.count { |result| result.fetch("accepted") }
puts "generated #{results.length} cases: #{accepted_count} accepted, #{results.length - accepted_count} rejected"
puts File.join(root, "manifest.json")
