import unittest

from ipsec_sentinel.traffic.video import resolve_video_plan, validate_video_result


class VideoGeneratorTest(unittest.TestCase):
    def test_plan_is_seeded_multi_segment_and_bounded(self) -> None:
        plan = resolve_video_plan(301)
        self.assertEqual(plan, resolve_video_plan(301))
        self.assertNotEqual(plan, resolve_video_plan(302))
        self.assertGreaterEqual(len(plan.segments), 5)
        self.assertGreater(
            sum(segment.expected_bytes for segment in plan.segments), 250_000
        )
        self.assertGreaterEqual(plan.target_duration_seconds, 4.0)
        self.assertTrue(
            all(segment.path.startswith("/video/segment-") for segment in plan.segments)
        )
        self.assertTrue(20_000 <= plan.preferred_port <= 29_999)
        self.assertNotEqual(plan.preferred_port, resolve_video_plan(302).preferred_port)

    def test_one_large_response_cannot_validate_as_video(self) -> None:
        plan = resolve_video_plan(301)
        one = [
            {
                "path": "/video/all.bin",
                "status": 200,
                "bytes": sum(item.expected_bytes for item in plan.segments),
            }
        ]
        validation = validate_video_result(
            plan,
            one,
            one,
            realized_duration_seconds=plan.target_duration_seconds,
        )
        self.assertFalse(validation.passed)
        self.assertTrue(any("segment" in error for error in validation.errors))

    def test_matching_segments_bytes_and_duration_pass(self) -> None:
        plan = resolve_video_plan(301)
        records = [
            {"path": item.path, "status": 200, "bytes": item.expected_bytes}
            for item in plan.segments
        ]
        validation = validate_video_result(
            plan,
            records,
            records,
            realized_duration_seconds=plan.target_duration_seconds,
        )
        self.assertTrue(validation.passed)


if __name__ == "__main__":
    unittest.main()
