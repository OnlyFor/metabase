import { useCallback, useMemo, useRef, useState } from "react";
import type { MouseEvent } from "react";
import { Icon } from "metabase/core/components/Icon";
import { Button, Group, Menu, Stack, Text, Box } from "metabase/ui";
import { isEmpty } from "metabase/lib/validate";
import { COMPARISON_SELECT_OPTIONS, COMPARISON_TYPES } from "./utils";
import {
  MenuItemStyled,
  MenuTargetStyled,
  NumberInputStyled,
} from "./SmartScalarSettingsWidgets.styled";

import type {
  ComparisonOption,
  SelectedComparison,
  SelectedComparisonPeriodsAgo,
} from "./utils";

interface SmartScalarComparisonWidgetProps {
  onChange: (setting: { type: string; value?: number }) => void;
  options: ComparisonOption[];
  value: SelectedComparison;
}

export function SmartScalarComparisonWidget({
  onChange,
  options,
  value: selectedValue,
}: SmartScalarComparisonWidgetProps) {
  const [open, setOpen] = useState(false);

  const selectedOption = options.find(
    ({ type }) => type === selectedValue.type,
  );

  const selectedDisplayName =
    selectedValue.type === COMPARISON_SELECT_OPTIONS.PERIODS_AGO.type
      ? `${selectedValue.value ?? ""} ${selectedOption?.name}`
      : selectedOption?.name;

  const isDisabled = options.length === 1 && !isEmpty(selectedOption);

  return (
    <Menu opened={open} onChange={setOpen} position="bottom-start" shadow="sm">
      <MenuTargetStyled>
        <Button pr="0" pl="1rem" disabled={isDisabled}>
          <Group spacing="sm">
            <span>{selectedDisplayName}</span>
            <Icon name="chevrondown" size="14" />
          </Group>
        </Button>
      </MenuTargetStyled>

      <Menu.Dropdown miw="18.25rem">
        <Stack spacing="sm">
          {options.map(({ type, name, MenuItemComponent, ...rest }) => {
            const givenValue =
              selectedValue.type === type ? selectedValue : null;

            if (MenuItemComponent) {
              return (
                <MenuItemComponent
                  key={type}
                  isSelected={selectedOption?.type === type}
                  type={type}
                  name={name}
                  onChange={onChange}
                  givenValue={givenValue}
                  setOpen={setOpen}
                  {...rest}
                />
              );
            }

            return (
              <MenuItemStyled
                key={type}
                isSelected={selectedOption?.type === type}
                onClick={() => onChange({ type })}
              >
                <Text fw="bold" ml="0.5rem">
                  {name}
                </Text>
              </MenuItemStyled>
            );
          })}
        </Stack>
      </Menu.Dropdown>
    </Menu>
  );
}

interface PeriodsAgoInputWidget {
  isSelected: boolean;
  maxValue: number;
  minValue: number;
  name: string;
  onChange: (setting: { type: string; value?: number }) => void;
  givenValue: SelectedComparisonPeriodsAgo | undefined;
  setOpen: (value: boolean) => void;
  type: string;
}

export function PeriodsAgoInputWidget({
  isSelected,
  maxValue,
  name,
  onChange,
  givenValue,
  setOpen,
  type,
}: PeriodsAgoInputWidget) {
  const value = useMemo(() => {
    if (!givenValue) {
      return null;
    }

    if (
      givenValue.type === COMPARISON_TYPES.PERIODS_AGO &&
      Number.isInteger(givenValue.value)
    ) {
      return givenValue.value;
    }

    return null;
  }, [givenValue]);
  const minValue = 2;

  const [inputValue, setInputValue] = useState(value ?? minValue);

  // used to prevent accidental button click when mouseDown inside input field
  // but dragged to highlight all text and accidentally mouseUp on the button
  // outside the input field
  const mouseDownInChild = useRef(false);
  const handleChildMouseDownAndUp = useCallback(
    (e: MouseEvent<HTMLInputElement>) => {
      e.stopPropagation();
      e.preventDefault();
      e.currentTarget.select();

      mouseDownInChild.current = true;
    },
    [],
  );
  const handleParentMouseDown = useCallback(() => {
    mouseDownInChild.current = false;
  }, []);

  const handleButtonClick = useCallback(
    (e: MouseEvent<HTMLDivElement>) => {
      e.stopPropagation();
      e.preventDefault();

      if (mouseDownInChild.current) {
        mouseDownInChild.current = false;
        return;
      }

      if (inputValue < minValue) {
        return setInputValue(minValue);
      }

      if (inputValue > maxValue) {
        return setInputValue(maxValue);
      }

      if (!Number.isInteger(inputValue)) {
        return setInputValue(value ?? minValue);
      }

      onChange({
        type,
        value: inputValue,
      });

      setOpen(false);
    },
    [inputValue, maxValue, type, onChange, setOpen, value],
  );

  return (
    <MenuItemStyled py="0.25rem" isSelected={isSelected}>
      <Box onClick={handleButtonClick} onMouseDown={handleParentMouseDown}>
        <Group position="apart" px="0.5rem">
          <Text fw="bold">{`${inputValue} ${name}`}</Text>
          <NumberInputStyled
            value={inputValue}
            onChange={(value: number) => setInputValue(value)}
            onMouseDown={handleChildMouseDownAndUp}
            onMouseUp={handleChildMouseDownAndUp}
            size="xs"
            w="3.5rem"
            type="number"
            required
          ></NumberInputStyled>
        </Group>
      </Box>
    </MenuItemStyled>
  );
}
