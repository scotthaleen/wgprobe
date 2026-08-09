class Wgprobe < Formula
  desc "Probe a WireGuard endpoint without creating a tunnel interface"
  homepage "https://github.com/scotthaleen/wgprobe"
  url "https://github.com/scotthaleen/wgprobe/archive/refs/tags/v0.1.1.tar.gz"
  sha256 "e8fe797b8fb72fe17f3d7a2857e1fdec57cb1aeb24bffebc9c6018a43050337c"
  license "MIT"
  head "https://github.com/scotthaleen/wgprobe.git", branch: "master"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/wgprobe")
  end

  test do
    assert_match "wgprobe 0.1.1", shell_output("#{bin}/wgprobe --version")
    assert_match "Usage: wgprobe", shell_output("#{bin}/wgprobe --help")
  end
end
