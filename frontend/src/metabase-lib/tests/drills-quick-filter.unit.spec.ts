import {
  createOrdersCreatedAtDatasetColumn,
  createOrdersTotalDatasetColumn,
  createReviewsBodyDatasetColumn,
  createReviewsReviewerDatasetColumn,
  REVIEWS_ID,
} from "metabase-types/api/mocks/presets";
import * as Lib from "metabase-lib";
import {
  createQuery,
  createRawCellClickObject,
  findDrillThru,
} from "metabase-lib/test-helpers";

describe("drill-thru/quick-filter", () => {
  const drillType = "drill-thru/quick-filter";
  const stageIndex = 0;

  describe("raw query", () => {
    const defaultQuery = createQuery();
    const expectedStageCount = 1;

    it("should drill a cell with null value", () => {
      const column = createOrdersTotalDatasetColumn();
      const clickObject = createRawCellClickObject({ column, value: null });
      const { drill, drillInfo } = findDrillThru(
        defaultQuery,
        stageIndex,
        clickObject,
        drillType,
      );
      expect(drillInfo).toMatchObject({ operators: ["=", "≠"] });
      verifyDrillThru(defaultQuery, drill, drillInfo, expectedStageCount);
    });

    it("should drill a cell for a numeric column", () => {
      const column = createOrdersTotalDatasetColumn();
      const clickObject = createRawCellClickObject({ column, value: 10 });
      const { drill, drillInfo } = findDrillThru(
        defaultQuery,
        stageIndex,
        clickObject,
        drillType,
      );
      expect(drillInfo).toMatchObject({ operators: ["<", ">", "=", "≠"] });
      verifyDrillThru(defaultQuery, drill, drillInfo, expectedStageCount);
    });

    it("should drill a cell for a date column", () => {
      const column = createOrdersCreatedAtDatasetColumn();
      const clickObject = createRawCellClickObject({
        column,
        value: "2020-01-01",
      });
      const { drill, drillInfo } = findDrillThru(
        defaultQuery,
        stageIndex,
        clickObject,
        drillType,
      );
      expect(drillInfo).toMatchObject({ operators: ["<", ">", "=", "≠"] });
      verifyDrillThru(defaultQuery, drill, drillInfo, expectedStageCount);
    });

    it("should drill a cell for a text column", () => {
      const query = Lib.withDifferentTable(defaultQuery, REVIEWS_ID);
      const column = createReviewsReviewerDatasetColumn();
      const clickObject = createRawCellClickObject({
        column,
        value: "text",
      });
      const { drill, drillInfo } = findDrillThru(
        query,
        stageIndex,
        clickObject,
        drillType,
      );
      expect(drillInfo).toMatchObject({
        operators: ["=", "≠"],
      });
      verifyDrillThru(query, drill, drillInfo, expectedStageCount);
    });

    it("should drill a cell for description or comment columns", () => {
      const query = Lib.withDifferentTable(defaultQuery, REVIEWS_ID);
      const column = createReviewsBodyDatasetColumn();
      const clickObject = createRawCellClickObject({
        column,
        value: "text",
      });
      const { drillInfo } = findDrillThru(
        query,
        stageIndex,
        clickObject,
        drillType,
      );
      expect(drillInfo).toMatchObject({
        operators: ["contains", "does-not-contain"],
      });
    });
  });
});

function verifyDrillThru(
  query: Lib.Query,
  drill: Lib.DrillThru,
  drillInfo: Lib.DrillThruDisplayInfo,
  expectedStageCount: number,
) {
  if (drillInfo.type === "drill-thru/quick-filter") {
    drillInfo.operators.forEach(operator => {
      const newQuery = Lib.drillThru(query, -1, drill, operator);
      expect(Lib.filters(newQuery, -1)).toHaveLength(1);
      expect(Lib.stageCount(newQuery)).toBe(expectedStageCount);
    });
  }
}
