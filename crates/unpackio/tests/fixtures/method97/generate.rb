# frozen_string_literal: true

# Generates deterministic project-authored RIFF/WAVE inputs and, when
# WAVPACK_ENCODER is set, WavPack 4 compatibility payloads for ZIP method 97.
# The external encoder is a test oracle only; unpackio never invokes it.

require "digest"
require "fileutils"

def chunk(id, payload)
  raise "chunk id must contain four bytes" unless id.bytesize == 4

  id + [payload.bytesize].pack("V") + payload + (payload.bytesize.odd? ? "\0" : "")
end

def wave(format, samples, trailer = nil)
  body = "WAVE" + chunk("fmt ", format) + chunk("data", samples)
  body += chunk("LIST", trailer) if trailer
  "RIFF" + [body.bytesize].pack("V") + body
end

def pcm_format(channels, rate, bits)
  bytes = (bits + 7) / 8
  align = channels * bytes
  [1, channels, rate, rate * align, align, bits].pack("vvVVvv")
end

def float_format(channels, rate)
  align = channels * 4
  [3, channels, rate, rate * align, align, 32].pack("vvVVvv")
end

def extensible_pcm_format(channels, rate, bits, mask)
  bytes = (bits + 7) / 8
  align = channels * bytes
  base = [0xfffe, channels, rate, rate * align, align, bits].pack("vvVVvv")
  subtype_pcm = [1].pack("V") + "\x00\x00\x10\x00\x80\x00\x00\xaa\x00\x38\x9b\x71".b
  base + [22, bits, mask].pack("vvV") + subtype_pcm
end

def signed24(value)
  encoded = value & 0x00ff_ffff
  [encoded & 0xff, (encoded >> 8) & 0xff, (encoded >> 16) & 0xff].pack("C3")
end

cases = {}
cases["pcm8_mono"] = wave(
  pcm_format(1, 8_000, 8),
  (0...65).map { |index| (index * 37 + 11) & 0xff }.pack("C*"),
  "INFOmethod97-pcm8"
)
cases["pcm16_stereo"] = wave(
  pcm_format(2, 44_100, 16),
  (0...64).flat_map { |index| [index * 701 - 20_000, 18_000 - index * 509] }.pack("s<*"),
  "INFOmethod97-pcm16"
)
cases["pcm16_custom_rate"] = wave(
  pcm_format(1, 12_345, 16),
  (0...47).map { |index| index * 431 - 9_000 }.pack("s<*"),
  "INFOmethod97-custom-rate"
)
cases["pcm24_stereo"] = wave(
  pcm_format(2, 48_000, 24),
  (0...48).flat_map do |index|
    [signed24(index * 123_457 - 2_500_000), signed24(2_000_000 - index * 91_117)]
  end.join,
  "INFOmethod97-pcm24"
)
cases["pcm32_mono"] = wave(
  pcm_format(1, 32_000, 32),
  (0...41).map { |index| index * 31_415_927 - 600_000_000 }.pack("l<*"),
  "INFOmethod97-pcm32"
)
float_bits = [
  0x0000_0000, 0x8000_0000, 0x3f80_0000, 0xbf80_0000,
  0x0000_0001, 0x007f_ffff, 0x7f80_0000, 0xff80_0000,
  0x7fc0_1234, 0xffc0_4321, 0x3eaa_aaab, 0xc049_0fdb
]
cases["float32_stereo"] = wave(
  float_format(2, 44_100),
  (float_bits * 2).pack("V*"),
  "INFOmethod97-float"
)
cases["pcm16_quad"] = wave(
  extensible_pcm_format(4, 48_000, 16, 0x33),
  (0...32).flat_map do |index|
    [index * 101 - 1_000, 2_000 - index * 73, index * 41 - 500, 700 - index * 29]
  end.pack("s<*"),
  "INFOmethod97-quad"
)
cases["pcm16_three_channel"] = wave(
  extensible_pcm_format(3, 32_000, 16, 0x7),
  (0...19).flat_map { |index| [index * 101 - 900, 1_100 - index * 61, index * 37 - 300] }.pack("s<*"),
  "INFOmethod97-three-channel"
)
cases["pcm16_sixteen_channel"] = wave(
  extensible_pcm_format(16, 48_000, 16, 0xffff),
  (0...9).flat_map { |frame| (0...16).map { |channel| frame * 71 + channel * 131 - 1_200 } }.pack("s<*"),
  "INFOmethod97-sixteen-channel"
)
cases["pcm16_multiblock"] = wave(
  pcm_format(1, 44_100, 16),
  "\0".b * (150_000 * 2),
  "INFOmethod97-multiblock"
)

root = File.expand_path(ARGV.fetch(0, "."))
FileUtils.mkdir_p(root)
encoder = ENV["WAVPACK_ENCODER"]

cases.each do |name, bytes|
  wav = File.join(root, "#{name}.wav")
  File.binwrite(wav, bytes)
  puts "#{name}.wav bytes=#{bytes.bytesize} sha256=#{Digest::SHA256.hexdigest(bytes)}"
  next unless encoder

  wv = File.join(root, "#{name}.wv")
  success = system(encoder, "-y", "-q", "-hh", wav, wv)
  raise "WavPack encoder failed for #{name}" unless success

  payload = File.binread(wv)
  puts "#{name}.wv bytes=#{payload.bytesize} sha256=#{Digest::SHA256.hexdigest(payload)}"
  puts payload.unpack1("H*")
end
