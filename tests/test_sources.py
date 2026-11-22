import unittest

from ru_routing.sources import named_hosts, plain_domains


class NamedHostsTest(unittest.TestCase):
    TEXT = """# copilot.microsoft.com
# software-static.download.prss.microsoft.com
microsoft.com

# 4pda.to/forum/index.php?showforum=1192
4pda.to

# Some Photoshop AI tools
adobe.io

# www.example.org
example.org
docker.io
"""

    def test_takes_named_hosts(self):
        self.assertEqual(list(named_hosts(self.TEXT)), [
            "copilot.microsoft.com", "software-static.download.prss.microsoft.com",
            "4pda.to", "adobe.io", "example.org", "docker.io"])

    def test_plain_keeps_whole_domains(self):
        self.assertEqual(list(plain_domains(self.TEXT)), ["microsoft.com", "4pda.to", "adobe.io", "example.org", "docker.io"])


if __name__ == "__main__":
    unittest.main()
