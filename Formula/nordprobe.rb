class Nordprobe < Formula
  desc "Browse and verify Nord WireGuard endpoints in a terminal UI"
  homepage "https://github.com/scotthaleen/wgprobe"
  url "https://github.com/scotthaleen/wgprobe/archive/113fedcc3fdfca16718cf60d0f0d4890100a18ae.tar.gz"
  version "0.1.0"
  sha256 "4b7999c21363a71dd96a5a4c54a345b18dde37648cfbecc7bf816af9f571252b"
  license "MIT"
  head "https://github.com/scotthaleen/wgprobe.git", branch: "master"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/nordprobe")
  end

  test do
    assert_match "nordprobe 0.1.0", shell_output("#{bin}/nordprobe --version")
    assert_match "Usage: nordprobe", shell_output("#{bin}/nordprobe --help")
  end
end
