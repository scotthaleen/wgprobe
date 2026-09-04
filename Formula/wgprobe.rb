class Wgprobe < Formula
  desc "Probe a WireGuard endpoint without creating a tunnel interface"
  homepage "https://github.com/scotthaleen/wgprobe"
  url "https://github.com/scotthaleen/wgprobe/archive/refs/tags/v0.1.6.tar.gz"
  sha256 "58d6bbf420aad06b1c15cf7783d948f1c55e1153fd9c5f1e212798c9dd383373"
  license "MIT"
  head "https://github.com/scotthaleen/wgprobe.git", branch: "master"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/wgprobe")
  end

  test do
    assert_match "wgprobe 0.1.6", shell_output("#{bin}/wgprobe --version")
    assert_match "Usage: wgprobe", shell_output("#{bin}/wgprobe --help")
  end
end
