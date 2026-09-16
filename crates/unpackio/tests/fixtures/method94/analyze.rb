# frozen_string_literal: true

# Derives and verifies only independently observable packMP3/PMP envelope
# fields from the committed MP3/PMP pairs. This script invokes no external
# encoder or decoder and deliberately makes no claim about the entropy stream
# that begins at byte 11.

require "base64"
require "json"
require "set"

BITRATES_KBPS = [
  nil, 32, 40, 48, 56, 64, 80, 96,
  112, 128, 160, 192, 224, 256, 320, nil
].freeze
SAMPLE_RATES = [44_100, 48_000, 32_000].freeze

Frame = Struct.new(
  :bitrate_index,
  :sample_rate_index,
  :channel_mode,
  :padding,
  :ms_stereo,
  :intensity_stereo,
  :has_crc,
  :copyright,
  :original,
  :emphasis,
  :main_data_begin,
  :scalefactor_sharing,
  :window_switching,
  :subblock_gain,
  :preemphasis,
  :coarse_scalefactors,
  keyword_init: true
)

def check(condition, message)
  raise message unless condition
end

def decode(path)
  Base64.strict_decode64(File.read(path).gsub(/\s+/, ""))
end

def leading_id3v2_size(mp3, name)
  return 0 unless mp3.start_with?("ID3")

  check(mp3.bytesize >= 10, "#{name}: truncated ID3v2 header")
  size_bytes = mp3.byteslice(6, 4).bytes
  check(size_bytes.all? { |byte| byte < 0x80 }, "#{name}: invalid ID3v2 synchsafe size")
  body_size = size_bytes.reduce(0) { |value, byte| (value << 7) | byte }
  footer_size = (mp3.getbyte(5) & 0x10).zero? ? 0 : 10
  size = 10 + body_size + footer_size
  check(size <= mp3.bytesize, "#{name}: ID3v2 tag exceeds input")
  size
end

def read_bits(bytes, position, count, name)
  check(count >= 0, "#{name}: negative bit count")
  check(position + count <= bytes.bytesize * 8, "#{name}: side information is truncated")
  value = 0
  count.times do |index|
    bit_position = position + index
    byte = bytes.getbyte(bit_position / 8)
    value = (value << 1) | ((byte >> (7 - (bit_position % 8))) & 1)
  end
  [value, position + count]
end

def parse_side_information(bytes, channels, name)
  position = 0
  main_data_begin, position = read_bits(bytes, position, 9, name)
  _, position = read_bits(bytes, position, channels == 1 ? 5 : 3, name)

  scalefactor_sharing = false
  channels.times do
    sharing, position = read_bits(bytes, position, 4, name)
    scalefactor_sharing ||= !sharing.zero?
  end

  window_switching = false
  subblock_gain = false
  preemphasis = false
  coarse_scalefactors = false
  2.times do
    channels.times do
      _, position = read_bits(bytes, position, 12 + 9 + 8 + 4, name)
      switching, position = read_bits(bytes, position, 1, name)
      window_switching ||= switching == 1
      if switching == 1
        _, position = read_bits(bytes, position, 2 + 1 + 5 + 5, name)
        3.times do
          gain, position = read_bits(bytes, position, 3, name)
          subblock_gain ||= !gain.zero?
        end
      else
        _, position = read_bits(bytes, position, 5 + 5 + 5 + 4 + 3, name)
      end
      preflag, position = read_bits(bytes, position, 1, name)
      scale, position = read_bits(bytes, position, 1, name)
      _, position = read_bits(bytes, position, 1, name)
      preemphasis ||= preflag == 1
      coarse_scalefactors ||= scale == 1
    end
  end

  check(position == bytes.bytesize * 8, "#{name}: side information was not consumed exactly")
  {
    main_data_begin: main_data_begin,
    scalefactor_sharing: scalefactor_sharing,
    window_switching: window_switching,
    subblock_gain: subblock_gain,
    preemphasis: preemphasis,
    coarse_scalefactors: coarse_scalefactors
  }
end

def parse_frames(mp3, name)
  has_id3v2 = mp3.start_with?("ID3")
  has_id3v1 = mp3.bytesize >= 128 && mp3.byteslice(-128, 3) == "TAG"
  offset = leading_id3v2_size(mp3, name)
  audio_end = mp3.bytesize - (has_id3v1 ? 128 : 0)
  frames = []

  while offset < audio_end
    check(audio_end - offset >= 4, "#{name}: truncated MPEG header")
    header = mp3.byteslice(offset, 4).unpack1("N")
    check((header & 0xffe0_0000) == 0xffe0_0000, "#{name}: MPEG sync differs")
    check(((header >> 19) & 0x3) == 0x3, "#{name}: stream is not MPEG-1")
    check(((header >> 17) & 0x3) == 0x1, "#{name}: stream is not Layer III")

    bitrate_index = (header >> 12) & 0xf
    sample_rate_index = (header >> 10) & 0x3
    bitrate = BITRATES_KBPS.fetch(bitrate_index)
    sample_rate = SAMPLE_RATES.fetch(sample_rate_index, nil)
    check(!bitrate.nil?, "#{name}: free or invalid bitrate index")
    check(!sample_rate.nil?, "#{name}: reserved sample-rate index")

    padding = (header >> 9) & 0x1
    frame_size = ((144_000 * bitrate) / sample_rate) + padding
    check(frame_size >= 6, "#{name}: impossible MPEG frame size")
    check(frame_size <= audio_end - offset, "#{name}: MPEG frame exceeds input")

    has_crc = ((header >> 16) & 0x1).zero?
    channel_mode = (header >> 6) & 0x3
    channels = channel_mode == 3 ? 1 : 2
    side_info = offset + 4 + (has_crc ? 2 : 0)
    side_info_size = channels == 1 ? 17 : 32
    check(side_info + side_info_size <= offset + frame_size, "#{name}: side information is truncated")
    side = parse_side_information(mp3.byteslice(side_info, side_info_size), channels, name)
    mode_extension = (header >> 4) & 0x3

    frames << Frame.new(
      bitrate_index: bitrate_index,
      sample_rate_index: sample_rate_index,
      channel_mode: channel_mode,
      padding: padding == 1,
      ms_stereo: channel_mode == 1 && (mode_extension & 0x2) != 0,
      intensity_stereo: channel_mode == 1 && (mode_extension & 0x1) != 0,
      has_crc: has_crc,
      copyright: ((header >> 3) & 0x1) == 1,
      original: ((header >> 2) & 0x1) == 1,
      emphasis: header & 0x3,
      main_data_begin: side.fetch(:main_data_begin),
      scalefactor_sharing: side.fetch(:scalefactor_sharing),
      window_switching: side.fetch(:window_switching),
      subblock_gain: side.fetch(:subblock_gain),
      preemphasis: side.fetch(:preemphasis),
      coarse_scalefactors: side.fetch(:coarse_scalefactors)
    )
    offset += frame_size
  end

  check(offset == audio_end, "#{name}: bytes remain outside parsed MPEG frames")
  check(!frames.empty?, "#{name}: no MPEG frames")
  [frames, has_id3v1, has_id3v2]
end

root = File.expand_path(ARGV.fetch(0, File.join(__dir__, "research")))
manifest = JSON.parse(File.read(File.join(root, "manifest.json")))
feature_flag_values = Set.new

manifest.fetch("cases").each do |entry|
  name = entry.fetch("name")
  pair_root = File.join(root, "pairs")
  mp3 = decode(File.join(pair_root, "#{name}.mp3.b64"))
  pmp = decode(File.join(pair_root, "#{name}.pmp.b64"))
  frames, has_id3v1, has_id3v2 = parse_frames(mp3, name)

  check(pmp.bytesize > 11, "#{name}: PMP stream has no entropy payload")
  check(pmp.byteslice(0, 3) == "MS\x0a".b, "#{name}: PMP signature differs")

  sample_rate_indices = frames.map(&:sample_rate_index).uniq
  channel_modes = frames.map(&:channel_mode).uniq
  bitrate_indices = frames.map(&:bitrate_index).uniq
  check(sample_rate_indices.length == 1, "#{name}: sample rate changes between frames")
  check(channel_modes.length == 1, "#{name}: channel mode changes between frames")
  fixed_bitrate = bitrate_indices.length == 1 ? bitrate_indices.first : 0
  descriptor = (sample_rate_indices.first << 6) | (channel_modes.first << 4) | fixed_bitrate
  check(pmp.getbyte(3) == descriptor, "#{name}: PMP stream descriptor differs")

  feature_flags = 0
  feature_flags |= 0x80 if frames.any?(&:padding)
  feature_flags |= 0x40 if frames.any?(&:ms_stereo)
  feature_flags |= 0x20 if frames.any?(&:intensity_stereo)
  feature_flags |= 0x10 if frames.any?(&:window_switching)
  feature_flags |= 0x08 if frames.any?(&:subblock_gain)
  feature_flags |= 0x04 if frames.any?(&:scalefactor_sharing)
  feature_flags |= 0x02 if frames.any?(&:preemphasis)
  feature_flags |= 0x01 if frames.any?(&:coarse_scalefactors)
  check(pmp.getbyte(4) == feature_flags, "#{name}: PMP feature flags differ")

  crc_values = frames.map(&:has_crc).uniq
  copyright_values = frames.map(&:copyright).uniq
  original_values = frames.map(&:original).uniq
  emphasis_values = frames.map(&:emphasis).uniq
  check(crc_values.length == 1, "#{name}: CRC protection changes between frames")
  check(copyright_values.length == 1, "#{name}: copyright flag changes between frames")
  check(original_values.length == 1, "#{name}: original flag changes between frames")
  check(emphasis_values.length == 1, "#{name}: emphasis changes between frames")

  flags = 0
  flags |= 0x80 if crc_values.first
  flags |= 0x40 if original_values.first
  flags |= 0x20 if copyright_values.first
  flags |= emphasis_values.first << 2
  flags |= 0x02 if has_id3v2
  flags |= 0x01 if has_id3v1
  check(pmp.getbyte(5) == flags, "#{name}: PMP global flags differ")

  reservoir = frames.any? { |frame| frame.main_data_begin.positive? } ? 0x80 : 0
  check(pmp.getbyte(6) == reservoir, "#{name}: PMP reservoir marker differs")
  check(pmp.byteslice(7, 4).unpack1("N") == frames.length, "#{name}: frame count differs")

  feature_flag_values.add(pmp.getbyte(4))
end

puts [
  "analyzed #{manifest.fetch('cases').length} method-94 pairs",
  "verified the 3-byte magic, descriptor, and feature flags",
  "verified global flags, reservoir marker, and big-endian frame count",
  "verified #{feature_flag_values.length} observed byte-4 feature combinations",
  "the byte-11 entropy stream remains opaque"
].join(", ")
