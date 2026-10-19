"""확정 분석 결과와 모듈 소유 캐시의 게시 경계(SPEC-36)."""


class AnalysisCache(dict):
    """Service-owned cache: replace a complete result without dropping owned module records."""

    RESULT_FIELDS = frozenset(("ds", "pyHashes", "symbolShape", "graph", "analysis",
                              "layerSuppressed", "layerFindings", "layerNotes", "meta"))
    def publish(self, result):
        """Validate all result fields before replacing them; module-owned entries survive."""
        if result.keys() != self.RESULT_FIELDS:
            raise ValueError("Incomplete or foreign analysis result fields")
        self.update(result)
