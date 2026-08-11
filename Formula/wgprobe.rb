class Wgprobe < Formula
  desc "Probe a WireGuard endpoint without creating a tunnel interface"
  homepage "https://github.com/scotthaleen/wgprobe"
  url "https://github.com/scotthaleen/wgprobe/archive/refs/tags/v0.1.3.tar.gz"
  sha256 "a52525f41614437386ec53eda3826c4c616eb66c1d13cdd8c29fb3e2bfb9b92d"
  license "MIT"
  head "https://github.com/scotthaleen/wgprobe.git", branch: "master"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/wgprobe")
  end

  test do
    assert_match "wgprobe 0.1.3", shell_output("#{bin}/wgprobe --version")
    assert_match "Usage: wgprobe", shell_output("#{bin}/wgprobe --help")
  end
end
