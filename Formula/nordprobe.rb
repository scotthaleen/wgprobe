class Nordprobe < Formula
  desc "Browse and verify Nord WireGuard endpoints in a terminal UI"
  homepage "https://github.com/scotthaleen/wgprobe"
  url "https://github.com/scotthaleen/wgprobe/archive/refs/tags/v0.1.3.tar.gz"
  sha256 "a52525f41614437386ec53eda3826c4c616eb66c1d13cdd8c29fb3e2bfb9b92d"
  license "MIT"
  head "https://github.com/scotthaleen/wgprobe.git", branch: "master"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/nordprobe")
  end

  test do
    assert_match "nordprobe 0.1.3", shell_output("#{bin}/nordprobe --version")
    assert_match "Usage: nordprobe", shell_output("#{bin}/nordprobe --help")
  end
end
