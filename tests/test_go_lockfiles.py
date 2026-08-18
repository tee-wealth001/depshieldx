import unittest

from depshieldx.ecosystems.go.lockfiles import parse_go_list_module_output

# Real (trimmed) `go list -m -json all` output -- captured from a real
# scratch module during development (`go mod init` + `go get
# github.com/pkg/errors@v0.9.1 golang.org/x/text@v0.14.0`), not
# hand-written from memory. Concatenated JSON objects, not a JSON array --
# confirmed directly this is what the real command prints.
GO_LIST_SAMPLE = """\
{
	"Path": "depshieldx-resolve",
	"Main": true,
	"Dir": "C:\\\\Users\\\\steph\\\\AppData\\\\Local\\\\Temp\\\\tmp123",
	"GoMod": "C:\\\\Users\\\\steph\\\\AppData\\\\Local\\\\Temp\\\\tmp123\\\\go.mod",
	"GoVersion": "1.26.6"
}
{
	"Path": "github.com/pkg/errors",
	"Version": "v0.9.1",
	"Time": "2020-01-14T19:47:44Z",
	"Indirect": true,
	"Dir": "C:\\\\Users\\\\steph\\\\go\\\\pkg\\\\mod\\\\github.com\\\\pkg\\\\errors@v0.9.1",
	"GoMod": "C:\\\\Users\\\\steph\\\\go\\\\pkg\\\\mod\\\\cache\\\\download\\\\github.com\\\\pkg\\\\errors\\\\@v\\\\v0.9.1.mod",
	"Sum": "h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=",
	"GoModSum": "h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0="
}
{
	"Path": "golang.org/x/text",
	"Version": "v0.14.0",
	"Indirect": true,
	"Sum": "h1:ScX5w1eTa3QqT8oi6+ziP7dTV1S2+ALU0bI+0zXKQ",
	"GoModSum": "h1:18ZOQIKpY8NJVqYksKHtTdi31H5itFRjB5/qKTNYzSU="
}
"""

# A `replace` directive pointing at a local filesystem path has no Version
# field -- confirmed directly against a real `replace ... => ../local-fork`
# entry in `go list -m -json all` output.
GO_LIST_WITH_LOCAL_REPLACE = """\
{"Path": "depshieldx-resolve", "Main": true}
{"Path": "github.com/pkg/errors", "Version": "v0.9.1"}
{"Path": "example.com/local-fork", "Dir": "/home/user/local-fork", "Main": false}
"""


class ParseGoListModuleOutputTests(unittest.TestCase):
    def test_parses_concatenated_json_objects(self):
        resolved = parse_go_list_module_output(GO_LIST_SAMPLE)

        self.assertEqual(resolved["github.com/pkg/errors"], "v0.9.1")
        self.assertEqual(resolved["golang.org/x/text"], "v0.14.0")

    def test_excludes_main_module(self):
        resolved = parse_go_list_module_output(GO_LIST_SAMPLE)

        self.assertNotIn("depshieldx-resolve", resolved)

    def test_excludes_entries_with_no_version(self):
        # A local `replace` target has no fetchable version -- there's
        # nothing to resolve or scan for it.
        resolved = parse_go_list_module_output(GO_LIST_WITH_LOCAL_REPLACE)

        self.assertEqual(resolved, {"github.com/pkg/errors": "v0.9.1"})

    def test_empty_output_returns_empty_dict(self):
        self.assertEqual(parse_go_list_module_output(""), {})

    def test_whitespace_only_output_returns_empty_dict(self):
        self.assertEqual(parse_go_list_module_output("   \n\n   "), {})


if __name__ == "__main__":
    unittest.main()
