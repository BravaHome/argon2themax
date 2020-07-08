export declare const argon2d: number;
export declare const argon2i: number;
export declare const argon2id: number;
export interface Options {
    hashLength?: number;
    timeCost?: number;
    memoryCost?: number;
    parallelism?: number;
    type?: number;
    raw?: boolean;
}
export interface NumericLimit {
    max: number;
    min: number;
}
export interface OptionLimits {
    hashLength: NumericLimit;
    memoryCost: NumericLimit;
    timeCost: NumericLimit;
    parallelism: NumericLimit;
}
export declare const defaults: Options;
export declare const limits: OptionLimits;
export declare const hash: (plain: Buffer | string, salt: Buffer, options?: Options) => Promise<string>;
export declare function generateSalt(length?: number): Promise<Buffer>;
export declare const verify: (hash: string, plain: Buffer | string) => Promise<boolean>;
export declare namespace Measurement {
    interface Timing {
        options: Options;
        computeTimeMs: number;
        hashCost: number;
    }
    interface TimingResult {
        timings: Timing[];
    }
    interface TimingOptions {
        maxTimeMs?: number;
        type?: number;
        saltLength?: number;
        plain?: string;
        statusCallback?: (timing: Timing) => boolean;
    }
    interface TimingStrategy {
        run(options: TimingOptions): Promise<TimingResult>;
        name: string;
    }
    interface TimingContext {
        strategy: TimingStrategy;
        accumulatedTimeMs: number;
        timingOptions: TimingOptions;
        startingOptions: Options;
        data: any;
        pendingResult: TimingResult;
    }
    abstract class TimingStrategyBase implements TimingStrategy {
        name: string;
        run(options: TimingOptions): Promise<TimingResult>;
        abstract onBeforeStart(context: TimingContext): void;
        abstract applyNextOptions(context: TimingContext, lastTiming: Timing, options: Options): boolean;
        isDone(context: TimingContext, lastTiming: Timing): boolean;
        generateSalt(context: TimingContext): Promise<Buffer>;
    }
    class MaxMemoryMarchStrategy extends TimingStrategyBase {
        name: string;
        onBeforeStart(context: TimingContext): void;
        applyNextOptions(context: TimingContext, lastTiming: Timing, options: Options): boolean;
    }
    class ClosestMatchStrategy extends TimingStrategyBase {
        name: string;
        onBeforeStart(context: TimingContext): void;
        applyNextOptions(context: TimingContext, lastTiming: Timing, options: Options): boolean;
        isDone(context: TimingContext, lastTiming: Timing): boolean;
    }
    enum TimingStrategyType {
        MaxMemoryMarch = 0,
        ClosestMatch = 1
    }
    function getTimingStrategy(type: TimingStrategyType): TimingStrategy;
    const defaultTimingStrategy: Measurement.TimingStrategy;
    const defaultTimingOptions: Measurement.TimingOptions;
    function generateTimings(options?: Measurement.TimingOptions, timingStrategy?: Measurement.TimingStrategy): Promise<Measurement.TimingResult>;
}
export declare namespace Selection {
    import Timing = Measurement.Timing;
    import TimingResult = Measurement.TimingResult;
    interface SelectionStrategy {
        initialize(timingResults: TimingResult): void;
        select(maxTimeMs: number): Timing;
        fastest(): Timing;
        slowest(): Timing;
        name: string;
    }
    abstract class LinearSelectionStrategy implements SelectionStrategy {
        name: string;
        private sortedTimings;
        private timingsCache;
        private fastestTiming;
        private slowestTiming;
        abstract getSortedTimings(timings: Timing[]): Timing[];
        initialize(timingResults: TimingResult): void;
        select(maxTimeMs: number): Timing;
        fastest(): Timing;
        slowest(): Timing;
    }
    class MaxCostSelectionStrategy extends LinearSelectionStrategy {
        name: string;
        getSortedTimings(timings: Timing[]): Timing[];
    }
    class ClosestMatchSelectionStrategy extends LinearSelectionStrategy {
        name: string;
        getSortedTimings(timings: Timing[]): Timing[];
    }
    enum SelectionStrategyType {
        MaxCost = 0,
        ClosestMatch = 1
    }
    function getSelectionStrategy(type: SelectionStrategyType): SelectionStrategy;
}
import TimingStrategyType = Measurement.TimingStrategyType;
import SelectionStrategyType = Selection.SelectionStrategyType;
import SelectionStrategy = Selection.SelectionStrategy;
export declare function getMaxOptionsWithStrategies(maxMs: number, timingStrategy: Measurement.TimingStrategy, selectionStrategy: SelectionStrategy): Promise<Options>;
export declare function getMaxOptions(maxMs?: number, timingStrategy?: TimingStrategyType, selectionStrategy?: SelectionStrategyType): Promise<Options>;
