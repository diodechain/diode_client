#!/usr/bin/env elixir

renames = %{
  "diode_darwin_arm64.zip" => "diode_darwin_arm64.zip",
  "diode_darwin_amd64.zip" => "diode_darwin_amd64.zip",
  "diode_windows_amd64.zip" => "diode_windows_amd64.zip",
}

unzip_rename = %{
  "diode_linux_arm.zip" => "diode_linux_arm.zip",
  "diode_linux_arm64.zip" => "diode_linux_arm64.zip",
  "diode_linux_amd64_bullseye.zip" => "diode_linux_amd64.zip",
  "macOS-ARM64.zip" => "diode_darwin_arm64.pkg",
  "macOS-X64.zip" => "diode_darwin_amd64.pkg",
}

File.mkdir_p!("out")
for {from, to} <- renames do
  File.cp!(from, "out/" <> to)
  IO.puts("out/" <> to)
end

for {from, to} <- unzip_rename do
  {:ok, [{_, binary}]} = :zip.unzip(~c"#{from}", [:memory])
  File.write!("out/" <> to, binary)
  IO.puts("out/" <> to)
end
