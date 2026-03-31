from contextlib import redirect_stdout
import io
import unittest
from unittest.mock import Mock, patch

from depshieldx.provenance import _cache_key, _run_verification_call, check_provenance_batch


def _response(payload):
    response = Mock()
    response.json.return_value = payload
    response.raise_for_status.return_value = None
    return response


class ProvenanceTests(unittest.TestCase):
    def test_run_verification_call_suppresses_output_when_requested(self):
        sink = io.StringIO()

        with redirect_stdout(sink):
            result = _run_verification_call(lambda: print("noisy verifier") or "ok", suppress_output=True)

        self.assertEqual(result, "ok")
        self.assertEqual(sink.getvalue(), "")

    @patch("depshieldx.provenance._attestation_verifier_cache_token", return_value="attestation_verifier:unavailable")
    def test_cache_key_changes_with_attestation_verifier_state(self, _mock_token):
        unavailable_key = _cache_key("demo", "1.0.0")

        with patch("depshieldx.provenance._attestation_verifier_cache_token", return_value="attestation_verifier:0.0.29"):
            available_key = _cache_key("demo", "1.0.0")

        self.assertNotEqual(unavailable_key, available_key)

    @patch("depshieldx.provenance._attestation_verifier_cache_token", return_value="attestation_verifier:0.0.29")
    def test_cache_key_changes_with_selected_artifacts(self, _mock_token):
        wheel_key = _cache_key("demo", "1.0.0", [{"filename": "demo-1.0.0-py3-none-any.whl"}])
        sdist_key = _cache_key("demo", "1.0.0", [{"filename": "demo-1.0.0.tar.gz"}])

        self.assertNotEqual(wheel_key, sdist_key)

    @patch("depshieldx.provenance.requests.get")
    def test_provenance_blocks_yanked_release(self, mock_get):
        mock_get.side_effect = [
            _response(
                {
                    "info": {
                        "home_page": "https://example.com",
                        "project_urls": {"Homepage": "https://example.com"},
                        "author_email": "maintainer@example.com",
                        "maintainer_email": "",
                    },
                    "urls": [
                        {
                            "yanked": True,
                            "filename": "demo-1.0.0-py3-none-any.whl",
                            "packagetype": "bdist_wheel",
                            "digests": {"sha256": "abc"},
                        }
                    ],
                }
            ),
            _response({"attestation_bundles": []}),
        ]

        result = check_provenance_batch({"demo": "1.0.0"})

        self.assertTrue(result["block"])
        self.assertIn("yanked", result["reason"])

    @patch("depshieldx.provenance.requests.get")
    def test_provenance_warns_for_source_only_release(self, mock_get):
        mock_get.side_effect = [
            _response(
                {
                    "info": {
                        "home_page": "",
                        "project_urls": {},
                        "author_email": "",
                        "maintainer_email": "",
                    },
                    "urls": [
                        {
                            "yanked": False,
                            "filename": "demo-0.1.0.tar.gz",
                            "packagetype": "sdist",
                            "digests": {"sha256": "abc"},
                        }
                    ],
                }
            ),
            _response({"attestation_bundles": []}),
        ]

        result = check_provenance_batch({"demo": "0.1.0"})

        self.assertFalse(result["block"])
        self.assertEqual(result["warnings"], [])
        self.assertTrue(any("source-only" in info for info in result["infos"]))

    @patch(
        "depshieldx.provenance._cryptographically_verify_attestations",
        return_value={
            "available": True,
            "verified": True,
            "attestation_count": 1,
            "verified_attestation_count": 1,
            "errors": [],
        },
    )
    @patch("depshieldx.provenance.requests.get")
    def test_provenance_records_verified_attestations_and_trusted_publisher(self, mock_get, _mock_verify):
        mock_get.side_effect = [
            _response(
                {
                    "info": {
                        "home_page": "https://example.com",
                        "project_urls": {"Source": "https://github.com/example/demo"},
                        "author_email": "maintainer@example.com",
                        "maintainer_email": "",
                    },
                    "urls": [
                        {
                            "yanked": False,
                            "filename": "demo-1.2.0-py3-none-any.whl",
                            "packagetype": "bdist_wheel",
                            "digests": {"sha256": "abc"},
                            "url": "https://files.pythonhosted.org/packages/demo-1.2.0-py3-none-any.whl",
                        }
                    ],
                }
            ),
            _response(
                {
                    "attestation_bundles": [
                        {
                            "publisher": {
                                "kind": "GitHub",
                                "repository": "example/demo",
                                "workflow": ".github/workflows/release.yml",
                            },
                            "attestations": [
                                {
                                    "version": 1,
                                    "verification_material": {
                                        "issuer": "https://token.actions.githubusercontent.com",
                                    },
                                    "envelope": {"statement": "opaque", "signature": "opaque"},
                                }
                            ],
                        }
                    ]
                }
            ),
        ]

        result = check_provenance_batch({"demo": "1.2.0"})

        self.assertFalse(result["block"])
        signals = result["details"][0]["signals"]
        self.assertTrue(signals["has_attestations"])
        self.assertTrue(signals["fully_attested"])
        self.assertTrue(signals["attestation_verification_available"])
        self.assertTrue(signals["fully_verified_attestations"])
        self.assertEqual(signals["verified_attestation_file_count"], 1)
        self.assertIsNone(signals["verification_failure"])
        self.assertIsNone(signals["verification_unavailable"])
        self.assertTrue(signals["trusted_publisher"])
        self.assertEqual(signals["publisher_repositories"], ["example/demo"])

    @patch(
        "depshieldx.provenance._cryptographically_verify_attestations",
        return_value={
            "available": True,
            "verified": False,
            "attestation_count": 1,
            "verified_attestation_count": 0,
            "errors": ["signature verification failed"],
        },
    )
    @patch("depshieldx.provenance.requests.get")
    def test_provenance_blocks_when_attestation_verification_fails(self, mock_get, _mock_verify):
        mock_get.side_effect = [
            _response(
                {
                    "info": {
                        "home_page": "https://example.com",
                        "project_urls": {"Source": "https://github.com/example/demo"},
                        "author_email": "maintainer@example.com",
                        "maintainer_email": "",
                    },
                    "urls": [
                        {
                            "yanked": False,
                            "filename": "demo-2.0.0-py3-none-any.whl",
                            "packagetype": "bdist_wheel",
                            "digests": {"sha256": "abc"},
                            "url": "https://files.pythonhosted.org/packages/demo-2.0.0-py3-none-any.whl",
                        }
                    ],
                }
            ),
            _response(
                {
                    "attestation_bundles": [
                        {
                            "publisher": {
                                "kind": "GitHub",
                                "repository": "example/demo",
                                "workflow": ".github/workflows/release.yml",
                            },
                            "attestations": [
                                {
                                    "version": 1,
                                    "verification_material": {
                                        "issuer": "https://token.actions.githubusercontent.com",
                                    },
                                    "envelope": {"statement": "opaque", "signature": "opaque"},
                                }
                            ],
                        }
                    ]
                }
            ),
        ]

        result = check_provenance_batch({"demo": "2.0.0"})

        self.assertTrue(result["block"])
        self.assertIn("attestation verification failed", result["reason"])
        failure = result["details"][0]["signals"]["verification_failure"]
        self.assertEqual(failure["filename"], "demo-2.0.0-py3-none-any.whl")
        self.assertEqual(failure["error"], "signature verification failed")

    @patch(
        "depshieldx.provenance._cryptographically_verify_attestations",
        return_value={
            "available": False,
            "verified": False,
            "attestation_count": 1,
            "verified_attestation_count": 0,
            "errors": [],
            "infrastructure_errors": ["Failed to refresh TUF metadata"],
        },
    )
    @patch("depshieldx.provenance.requests.get")
    def test_provenance_warns_when_attestation_infrastructure_is_unavailable(self, mock_get, _mock_verify):
        mock_get.side_effect = [
            _response(
                {
                    "info": {
                        "home_page": "https://example.com",
                        "project_urls": {"Source": "https://github.com/example/demo"},
                        "author_email": "maintainer@example.com",
                        "maintainer_email": "",
                    },
                    "urls": [
                        {
                            "yanked": False,
                            "filename": "demo-2.1.0-py3-none-any.whl",
                            "packagetype": "bdist_wheel",
                            "digests": {"sha256": "abc"},
                            "url": "https://files.pythonhosted.org/packages/demo-2.1.0-py3-none-any.whl",
                        }
                    ],
                }
            ),
            _response(
                {
                    "attestation_bundles": [
                        {
                            "publisher": {
                                "kind": "GitHub",
                                "repository": "example/demo",
                                "workflow": ".github/workflows/release.yml",
                            },
                            "attestations": [
                                {
                                    "version": 1,
                                    "verification_material": {
                                        "issuer": "https://token.actions.githubusercontent.com",
                                    },
                                    "envelope": {"statement": "opaque", "signature": "opaque"},
                                }
                            ],
                        }
                    ]
                }
            ),
        ]

        result = check_provenance_batch({"demo": "2.1.0"})

        self.assertFalse(result["block"])
        self.assertEqual(result["warnings"], [])
        self.assertTrue(any("verification unavailable" in info for info in result["infos"]))
        signals = result["details"][0]["signals"]
        self.assertFalse(signals["attestation_verification_available"])
        unavailable = signals["verification_unavailable"]
        self.assertEqual(unavailable["filename"], "demo-2.1.0-py3-none-any.whl")
        self.assertEqual(unavailable["error"], "Failed to refresh TUF metadata")

    @patch(
        "depshieldx.provenance._cryptographically_verify_attestations",
        side_effect=[
            {
                "available": True,
                "verified": True,
                "attestation_count": 1,
                "verified_attestation_count": 1,
                "errors": [],
            },
        ],
    )
    @patch("depshieldx.provenance.requests.get")
    def test_provenance_uses_selected_artifacts_instead_of_all_release_files(self, mock_get, _mock_verify):
        mock_get.side_effect = [
            _response(
                {
                    "info": {
                        "home_page": "https://example.com",
                        "project_urls": {"Source": "https://github.com/example/demo"},
                        "author_email": "maintainer@example.com",
                        "maintainer_email": "",
                    },
                    "urls": [
                        {
                            "yanked": False,
                            "filename": "demo-3.0.0-py3-none-any.whl",
                            "packagetype": "bdist_wheel",
                            "digests": {"sha256": "abc"},
                            "url": "https://files.pythonhosted.org/packages/demo-3.0.0-py3-none-any.whl",
                        },
                        {
                            "yanked": False,
                            "filename": "demo-3.0.0.tar.gz",
                            "packagetype": "sdist",
                            "digests": {"sha256": "def"},
                            "url": "https://files.pythonhosted.org/packages/demo-3.0.0.tar.gz",
                        },
                    ],
                }
            ),
            _response(
                {
                    "attestation_bundles": [
                        {
                            "publisher": {
                                "kind": "GitHub",
                                "repository": "example/demo",
                                "workflow": ".github/workflows/release.yml",
                            },
                            "attestations": [
                                {
                                    "version": 1,
                                    "verification_material": {
                                        "issuer": "https://token.actions.githubusercontent.com",
                                    },
                                    "envelope": {"statement": "opaque", "signature": "opaque"},
                                }
                            ],
                        }
                    ]
                }
            ),
        ]

        result = check_provenance_batch(
            {"demo": "3.0.0"},
            selected_artifacts={
                "demo": [
                    {
                        "filename": "demo-3.0.0-py3-none-any.whl",
                        "url": "https://files.pythonhosted.org/packages/demo-3.0.0-py3-none-any.whl",
                        "digests": {"sha256": "abc"},
                    }
                ]
            },
        )

        self.assertFalse(result["block"])
        signals = result["details"][0]["signals"]
        self.assertEqual(signals["attested_file_count"], 1)
        self.assertEqual(signals["verified_attestation_file_count"], 1)

    @patch(
        "depshieldx.provenance._cryptographically_verify_attestations",
        return_value={
            "available": True,
            "verified": True,
            "attestation_count": 2,
            "verified_attestation_count": 1,
            "errors": [],
        },
    )
    @patch("depshieldx.provenance.requests.get")
    def test_provenance_accepts_file_when_at_least_one_attestation_verifies(self, mock_get, _mock_verify):
        mock_get.side_effect = [
            _response(
                {
                    "info": {
                        "home_page": "https://example.com",
                        "project_urls": {"Source": "https://github.com/example/demo"},
                        "author_email": "maintainer@example.com",
                        "maintainer_email": "",
                    },
                    "urls": [
                        {
                            "yanked": False,
                            "filename": "demo-4.0.0-py3-none-any.whl",
                            "packagetype": "bdist_wheel",
                            "digests": {"sha256": "abc"},
                            "url": "https://files.pythonhosted.org/packages/demo-4.0.0-py3-none-any.whl",
                        }
                    ],
                }
            ),
            _response(
                {
                    "attestation_bundles": [
                        {
                            "publisher": {
                                "kind": "GitHub",
                                "repository": "example/demo",
                                "workflow": ".github/workflows/release.yml",
                            },
                            "attestations": [
                                {
                                    "version": 1,
                                    "verification_material": {
                                        "issuer": "https://token.actions.githubusercontent.com",
                                    },
                                    "envelope": {"statement": "opaque1", "signature": "opaque1"},
                                },
                                {
                                    "version": 1,
                                    "verification_material": {
                                        "issuer": "https://token.actions.githubusercontent.com",
                                    },
                                    "envelope": {"statement": "opaque2", "signature": "opaque2"},
                                },
                            ],
                        }
                    ]
                }
            ),
        ]

        result = check_provenance_batch({"demo": "4.0.0"})

        self.assertFalse(result["block"])
        signals = result["details"][0]["signals"]
        self.assertTrue(signals["fully_verified_attestations"])
        self.assertEqual(signals["verified_attestation_count"], 1)
