import os
import unittest
from unittest.mock import patch

import azure_client
import analysis_engine


class AzureClientProfileTests(unittest.TestCase):
    def test_deep_profile_reads_prefixed_model(self):
        with patch.dict(
            os.environ,
            {
                "DEEP_OPENAI_API_KEY": "key",
                "DEEP_OPENAI_MODEL": "kimi-k2",
                "DEEP_OPENAI_BASE_URL": "https://example.com/v1",
            },
            clear=True,
        ):
            provider = azure_client.get_provider(profile="deep")
            self.assertEqual(provider, "openai")
            missing = azure_client.get_missing_config(profile="deep")
            self.assertEqual(missing["openai"], [])
            self.assertEqual(missing["azure"], [])


class AnalysisEngineApiFallbackTests(unittest.TestCase):
    def test_invoke_model_falls_back_to_responses_when_chat_rejected(self):
        class FakeChat:
            class completions:
                @staticmethod
                def create(**kwargs):
                    raise Exception("Unsupported parameter: 'messages'")

        class FakeResponses:
            @staticmethod
            def create(**kwargs):
                class Resp:
                    output_text = "ok-from-responses"
                    usage = {"total_tokens": 1}

                return Resp()

        class FakeClient:
            chat = FakeChat()
            responses = FakeResponses()

        with patch("analysis_engine.get_api_style", return_value="auto"):
            content, usage = analysis_engine._invoke_model(
                FakeClient(),
                "demo-model",
                "prompt",
                200,
                profile="default",
            )

        self.assertEqual(content, "ok-from-responses")
        self.assertEqual(usage, {"total_tokens": 1})


if __name__ == "__main__":
    unittest.main()
