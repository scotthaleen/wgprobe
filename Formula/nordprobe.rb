class Nordprobe < Formula
  desc "Browse and verify Nord WireGuard endpoints in a terminal UI"
  homepage "https://github.com/scotthaleen/wgprobe"
  url "https://github.com/scotthaleen/wgprobe/archive/refs/tags/v0.1.1.tar.gz"
  version "0.1.1"
  sha256 "e8fe797b8fb72fe17f3d7a2857e1fdec57cb1aeb24bffebc9c6018a43050337c"
  license "MIT"
  head "https://github.com/scotthaleen/wgprobe.git", branch: "master"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/nordprobe")
  end

  test do
    assert_match "nordprobe 0.1.1", shell_output("#{bin}/nordprobe --version")
    assert_match "Usage: nordprobe", shell_output("#{bin}/nordprobe --help")
  end
end
