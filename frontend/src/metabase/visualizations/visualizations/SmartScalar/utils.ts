import dayjs from "dayjs";
import { t } from "ttag";

import type {
  DatasetColumn,
  RawSeries,
  RowValues,
} from "metabase-types/api/dataset";
import type {
  RelativeDatetimeUnit,
  VisualizationSettings,
} from "metabase-types/api";

import { isEmpty } from "metabase/lib/validate";
import { formatNumber } from "metabase/lib/formatting";
import { measureText } from "metabase/lib/measure-text";
import { isDate } from "metabase-lib/types/utils/isa";
import { PeriodsAgoInputWidget } from "./SmartScalarSettingsWidgets";

import {
  ICON_MARGIN_RIGHT,
  ICON_SIZE,
  PERIOD_HIDE_HEIGHT_THRESHOLD,
  PREVIOUS_VALUE_SIZE,
  SCALAR_TITLE_LINE_HEIGHT,
  SPACING,
} from "./constants";

export const isPeriodVisible = (height: number) =>
  height > PERIOD_HIDE_HEIGHT_THRESHOLD;

export const formatChangeAutoPrecision = (
  change: number,
  {
    fontFamily,
    fontWeight,
    width,
  }: { fontFamily: string; fontWeight: number; width: number },
): string =>
  [2, 1]
    .map(n => formatChange(change, { maximumFractionDigits: n }))
    .find(
      formatted =>
        measureText(formatted, {
          size: "1rem",
          family: fontFamily,
          weight: fontWeight,
        }).width <= width,
    ) ?? formatChange(change, { maximumFractionDigits: 0 });

export const formatChange = (
  change: number,
  { maximumFractionDigits = 2 } = {},
): string => {
  const n = Math.abs(change);
  return n === Infinity
    ? "∞%"
    : formatNumber(n, { number_style: "percent", maximumFractionDigits });
};

export const getValueWidth = (width: number): number => {
  return getWidthWithoutSpacing(width);
};

const getWidthWithoutSpacing = (width: number) => {
  return Math.max(width - 2 * SPACING, 0);
};

export const getValueHeight = (height: number): number => {
  const valueHeight =
    height -
    (isPeriodVisible(height) ? SCALAR_TITLE_LINE_HEIGHT : 0) -
    PREVIOUS_VALUE_SIZE -
    4 * SPACING;

  return Math.max(valueHeight, 0);
};

export const getChangeWidth = (width: number): number => {
  return Math.max(width - ICON_SIZE - ICON_MARGIN_RIGHT - 2 * SPACING, 0);
};

export const COMPARISON_TYPES = {
  PREVIOUS_VALUE: "previousValue",
  PREVIOUS_PERIOD: "previousPeriod",
  PERIODS_AGO: "periodsAgo",
} as const;

const PLACEHOLDER_STR = "[placeholder]";
export const COMPARISON_SELECT_OPTIONS = {
  PREVIOUS_PERIOD: {
    type: COMPARISON_TYPES.PREVIOUS_PERIOD,
    nameTemplate: t`Previous ${PLACEHOLDER_STR}`,
  },
  PERIODS_AGO: {
    type: COMPARISON_TYPES.PERIODS_AGO,
    nameTemplate: t`${PLACEHOLDER_STR} ago`,
    MenuItemComponent: PeriodsAgoInputWidget,
  },
  COMPARE_TO_PREVIOUS: {
    type: COMPARISON_TYPES.PREVIOUS_VALUE,
    name: t`Previous value`,
  },
};

export type ComparisonOption = {
  type:
    | typeof COMPARISON_TYPES.PREVIOUS_VALUE
    | typeof COMPARISON_TYPES.PREVIOUS_PERIOD
    | typeof COMPARISON_TYPES.PERIODS_AGO;
  name: string;
  MenuItemComponent?: React.ComponentType<any>;
  maxValue?: number;
};

export type SelectedComparisonPeriodsAgo = {
  type: typeof COMPARISON_TYPES.PERIODS_AGO;
  value: number;
};
type SelectedComparisonPreviousPeriod = {
  type: typeof COMPARISON_TYPES.PREVIOUS_PERIOD;
};
type SelectedComparisonCompareToPrevious = {
  type: typeof COMPARISON_TYPES.PREVIOUS_VALUE;
};

export type SelectedComparison =
  | SelectedComparisonCompareToPrevious
  | SelectedComparisonPreviousPeriod
  | SelectedComparisonPeriodsAgo;

export function getDefaultComparison(
  series: RawSeries,
  settings: VisualizationSettings,
) {
  const [
    {
      data: { insights },
    },
  ] = series;

  const dateUnit = insights?.find(
    insight => insight.col === settings["scalar.field"],
  )?.unit;

  if (!dateUnit) {
    return COMPARISON_SELECT_OPTIONS.COMPARE_TO_PREVIOUS;
  }

  return {
    ...COMPARISON_SELECT_OPTIONS.PREVIOUS_PERIOD,
    name: COMPARISON_SELECT_OPTIONS.PREVIOUS_PERIOD.nameTemplate.replace(
      PLACEHOLDER_STR,
      t`${dateUnit}`,
    ),
  };
}

export function getComparisonOptions(
  series: RawSeries,
  settings: VisualizationSettings,
) {
  const [
    {
      data: { cols, insights, rows },
    },
  ] = series;

  const dateUnit = insights?.find(
    insight => insight.col === settings["scalar.field"],
  )?.unit as RelativeDatetimeUnit | undefined;

  if (!dateUnit) {
    return [COMPARISON_SELECT_OPTIONS.COMPARE_TO_PREVIOUS];
  }

  const options: ComparisonOption[] = [
    {
      ...COMPARISON_SELECT_OPTIONS.PREVIOUS_PERIOD,
      name: COMPARISON_SELECT_OPTIONS.PREVIOUS_PERIOD.nameTemplate.replace(
        PLACEHOLDER_STR,
        t`${dateUnit}`,
      ),
    },
  ];

  const maxPeriodsAgo = getMaxPeriodsAgo({ cols, rows, dateUnit });

  // only add this option is # number of selectable periods ago is >= 2
  // since we already have an option for 1 period ago -> PREVIOUS_PERIOD
  if (maxPeriodsAgo && maxPeriodsAgo >= 2) {
    options.push({
      ...COMPARISON_SELECT_OPTIONS.PERIODS_AGO,
      name: COMPARISON_SELECT_OPTIONS.PERIODS_AGO.nameTemplate.replace(
        PLACEHOLDER_STR,
        t`${dateUnit}s`,
      ),
      maxValue: maxPeriodsAgo,
    });
  }

  options.push(COMPARISON_SELECT_OPTIONS.COMPARE_TO_PREVIOUS);

  return options;
}

export function isComparisonValid(
  series: RawSeries,
  settings: VisualizationSettings,
) {
  const [
    {
      data: { insights },
    },
  ] = series;

  const dateUnit = insights?.find(
    insight => insight.col === settings["scalar.field"],
  )?.unit;

  if (!dateUnit) {
    return false;
  }

  return true;
}

type getMaxPeriodsAgoParameters = {
  cols: DatasetColumn[];
  rows: RowValues[];
  dateUnit: RelativeDatetimeUnit;
};

function getMaxPeriodsAgo({
  cols,
  rows,
  dateUnit,
}: getMaxPeriodsAgoParameters) {
  const dimensionIndex = cols.findIndex(col => isDate(col));

  if (dimensionIndex === -1) {
    return null;
  }

  const latestNonEmptyRow = rows.findLast(row => !isEmpty(row[dimensionIndex]));
  const earliestNonEmptyRow = rows.find(row => !isEmpty(row[dimensionIndex]));

  if (latestNonEmptyRow === undefined || earliestNonEmptyRow === undefined) {
    return null;
  }

  const latestNonEmptyDate = latestNonEmptyRow[dimensionIndex] as string;
  const earliestNonEmptyDate = earliestNonEmptyRow[dimensionIndex] as string;

  if (latestNonEmptyDate === null || earliestNonEmptyDate === null) {
    return null;
  }

  return dayjs(latestNonEmptyDate).diff(earliestNonEmptyDate, dateUnit);
}
