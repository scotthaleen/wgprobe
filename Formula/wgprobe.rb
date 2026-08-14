class Wgprobe < Formula
  desc "Probe a WireGuard endpoint without creating a tunnel interface"
  homepage "https://github.com/scotthaleen/wgprobe"
  url "https://github.com/scotthaleen/wgprobe/archive/refs/tags/v0.1.4.tar.gz"
  sha256 "eb09b2d05b35442fde61bdf2839ffa7f0a6cd3574540c70040dea84e8095f732"
  license "MIT"
  head "https://github.com/scotthaleen/wgprobe.git", branch: "master"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/wgprobe")
  end

  test do
    assert_match "wgprobe 0.1.4", shell_output("#{bin}/wgprobe --version")
    assert_match "Usage: wgprobe", shell_output("#{bin}/wgprobe --help")
  end
end
