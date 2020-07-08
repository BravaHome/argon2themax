"use strict";

var _possibleConstructorReturn2 = require("babel-runtime/helpers/possibleConstructorReturn");

var _possibleConstructorReturn3 = _interopRequireDefault(_possibleConstructorReturn2);

var _inherits2 = require("babel-runtime/helpers/inherits");

var _inherits3 = _interopRequireDefault(_inherits2);

var _regenerator = require("babel-runtime/regenerator");

var _regenerator2 = _interopRequireDefault(_regenerator);

var _classCallCheck2 = require("babel-runtime/helpers/classCallCheck");

var _classCallCheck3 = _interopRequireDefault(_classCallCheck2);

var _createClass2 = require("babel-runtime/helpers/createClass");

var _createClass3 = _interopRequireDefault(_createClass2);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var __awaiter = undefined && undefined.__awaiter || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) {
            try {
                step(generator.next(value));
            } catch (e) {
                reject(e);
            }
        }
        function rejected(value) {
            try {
                step(generator["throw"](value));
            } catch (e) {
                reject(e);
            }
        }
        function step(result) {
            result.done ? resolve(result.value) : new P(function (resolve) {
                resolve(result.value);
            }).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
/// <reference types="node" />
var os = require("os");
var _ = require("lodash");
var crypto = require("crypto");
// Begin Argon2 cloned interface for ease of use
exports.argon2d = 0;
exports.argon2i = 1;
exports.argon2id = 2;
var argon2lib = require("argon2");
exports.defaults = argon2lib.defaults;
exports.limits = argon2lib.limits;
exports.hash = argon2lib.hash;
// This used to be defined in argon2lib.generateSalt but then being remove
// https://github.com/ranisalt/node-argon2/commit/72fed64dc752a97613a0a63143b810b35ee69abf#diff-04c6e90faac2675aa89e2176d2eec7d8L24
function _generateSalt(length) {
    return new Promise(function (resolve, reject) {
        crypto.randomBytes(length || 16, function (err, salt) {
            if (err) {
                reject(err);
            }
            resolve(salt);
        });
    });
}
exports.generateSalt = _generateSalt;
exports.verify = argon2lib.verify;
// End Argon2 cloned interface for ease of use
var Measurement;
(function (Measurement) {
    var TimingStrategyBase = function () {
        function TimingStrategyBase() {
            (0, _classCallCheck3.default)(this, TimingStrategyBase);
        }

        (0, _createClass3.default)(TimingStrategyBase, [{
            key: "run",
            value: function run(options) {
                return __awaiter(this, void 0, void 0, /*#__PURE__*/_regenerator2.default.mark(function _callee() {
                    var opts, context, salt, i, lastTiming, startHrtime, elapsedHrtime, msElapsed;
                    return _regenerator2.default.wrap(function _callee$(_context) {
                        while (1) {
                            switch (_context.prev = _context.next) {
                                case 0:
                                    opts = _.clone(exports.defaults);

                                    opts.type = options.type;
                                    context = {
                                        accumulatedTimeMs: 0,
                                        data: {},
                                        startingOptions: opts,
                                        strategy: this,
                                        timingOptions: options,
                                        pendingResult: {
                                            timings: []
                                        }
                                    };

                                    this.onBeforeStart(context);
                                    // We'll mutate these options, so we clone them to not affect the startingOptions
                                    opts = _.clone(opts);
                                    _context.next = 7;
                                    return this.generateSalt(context);

                                case 7:
                                    salt = _context.sent;
                                    i = 0;

                                case 9:
                                    if (!(i < 3)) {
                                        _context.next = 15;
                                        break;
                                    }

                                    _context.next = 12;
                                    return exports.hash(options.plain, salt, opts);

                                case 12:
                                    i++;
                                    _context.next = 9;
                                    break;

                                case 15:
                                    lastTiming = void 0;

                                case 16:
                                    startHrtime = process.hrtime();
                                    _context.next = 19;
                                    return exports.hash(options.plain, salt, opts);

                                case 19:
                                    elapsedHrtime = process.hrtime(startHrtime);
                                    msElapsed = elapsedHrtime[0] * 1e3 + elapsedHrtime[1] / 1e6;

                                    context.accumulatedTimeMs += msElapsed;
                                    lastTiming = {
                                        computeTimeMs: msElapsed,
                                        options: _.clone(opts),
                                        hashCost: opts.memoryCost * opts.parallelism * opts.timeCost
                                    };
                                    context.pendingResult.timings.push(lastTiming);
                                    // Allow the callback to cancel the process if it feels the urge

                                    if (!(options.statusCallback && !options.statusCallback(lastTiming))) {
                                        _context.next = 26;
                                        break;
                                    }

                                    return _context.abrupt("break", 29);

                                case 26:
                                    if (this.applyNextOptions(context, lastTiming, opts)) {
                                        _context.next = 28;
                                        break;
                                    }

                                    return _context.abrupt("break", 29);

                                case 28:
                                    if (!this.isDone(context, lastTiming)) {
                                        _context.next = 16;
                                        break;
                                    }

                                case 29:
                                    return _context.abrupt("return", context.pendingResult);

                                case 30:
                                case "end":
                                    return _context.stop();
                            }
                        }
                    }, _callee, this);
                }));
            }
        }, {
            key: "isDone",
            value: function isDone(context, lastTiming) {
                return lastTiming.computeTimeMs >= context.timingOptions.maxTimeMs;
            }
        }, {
            key: "generateSalt",
            value: function generateSalt(context) {
                return _generateSalt(context.timingOptions.saltLength);
            }
        }]);
        return TimingStrategyBase;
    }();

    Measurement.TimingStrategyBase = TimingStrategyBase;

    var MaxMemoryMarchStrategy = function (_TimingStrategyBase) {
        (0, _inherits3.default)(MaxMemoryMarchStrategy, _TimingStrategyBase);

        function MaxMemoryMarchStrategy() {
            (0, _classCallCheck3.default)(this, MaxMemoryMarchStrategy);

            var _this = (0, _possibleConstructorReturn3.default)(this, (MaxMemoryMarchStrategy.__proto__ || Object.getPrototypeOf(MaxMemoryMarchStrategy)).apply(this, arguments));

            _this.name = "maxmemory";
            return _this;
        }

        (0, _createClass3.default)(MaxMemoryMarchStrategy, [{
            key: "onBeforeStart",
            value: function onBeforeStart(context) {
                context.startingOptions.parallelism = context.data.parallelism = Math.max(Math.min(os.cpus().length * 2, exports.limits.parallelism.max), exports.limits.parallelism.min);
                context.data.memoryCostMax = Math.min(Math.floor(Math.log2(os.totalmem() / 1024)), exports.limits.memoryCost.max);
            }
        }, {
            key: "applyNextOptions",
            value: function applyNextOptions(context, lastTiming, options) {
                // Prefer adding more memory, then add more time
                if (options.memoryCost < context.data.memoryCostMax) {
                    options.memoryCost++;
                } else if (options.timeCost < exports.limits.timeCost.max) {
                    options.memoryCost = exports.defaults.memoryCost;
                    options.timeCost++;
                } else {
                    // Hit both the memory and time limits -- Is this a supercomputer?
                    return false;
                }
                return true;
            }
        }]);
        return MaxMemoryMarchStrategy;
    }(TimingStrategyBase);

    Measurement.MaxMemoryMarchStrategy = MaxMemoryMarchStrategy;

    var ClosestMatchStrategy = function (_TimingStrategyBase2) {
        (0, _inherits3.default)(ClosestMatchStrategy, _TimingStrategyBase2);

        function ClosestMatchStrategy() {
            (0, _classCallCheck3.default)(this, ClosestMatchStrategy);

            var _this2 = (0, _possibleConstructorReturn3.default)(this, (ClosestMatchStrategy.__proto__ || Object.getPrototypeOf(ClosestMatchStrategy)).apply(this, arguments));

            _this2.name = "closestmatch";
            return _this2;
        }

        (0, _createClass3.default)(ClosestMatchStrategy, [{
            key: "onBeforeStart",
            value: function onBeforeStart(context) {
                context.startingOptions.parallelism = context.data.parallelism = Math.max(Math.min(os.cpus().length * 2, exports.limits.parallelism.max), exports.limits.parallelism.min);
                context.data.memoryCostMax = Math.min(Math.floor(Math.log2(os.totalmem() / 1024)), exports.limits.memoryCost.max);
                context.data.isDone = false;
                context.data.lastOvershot = false;
            }
        }, {
            key: "applyNextOptions",
            value: function applyNextOptions(context, lastTiming, options) {
                // Find every timeCost at a every memory cost that satisfies the timing threshold
                // Add more time until the timing threshold is reached.
                // Then go back to default timeCost and add memory.
                // Repeat until the first attempt at a given memory cost fails or we reached the max memory.
                if (lastTiming.computeTimeMs >= context.timingOptions.maxTimeMs) {
                    // Two in a row means we are done.
                    if (context.data.lastOvershot) {
                        return !(context.data.isDone = true);
                    }
                    // Increase memory and reduce timeCost to default to try next memory option.
                    if (options.memoryCost < exports.limits.memoryCost.max) {
                        options.timeCost = context.startingOptions.timeCost;
                        options.memoryCost++;
                        context.data.lastOvershot = true;
                    } else {
                        return !(context.data.isDone = true);
                    }
                } else {
                    context.data.lastOvershot = false;
                    if (options.timeCost < exports.limits.timeCost.max) {
                        options.timeCost++;
                    } else {
                        // Wow, really shouldn't hit max timeCost ever.
                        return !(context.data.isDone = true);
                    }
                }
                return true;
            }
        }, {
            key: "isDone",
            value: function isDone(context, lastTiming) {
                return !!context.data.isDone;
            }
        }]);
        return ClosestMatchStrategy;
    }(TimingStrategyBase);

    Measurement.ClosestMatchStrategy = ClosestMatchStrategy;
    var TimingStrategyType = void 0;
    (function (TimingStrategyType) {
        TimingStrategyType[TimingStrategyType["MaxMemoryMarch"] = 0] = "MaxMemoryMarch";
        TimingStrategyType[TimingStrategyType["ClosestMatch"] = 1] = "ClosestMatch";
    })(TimingStrategyType = Measurement.TimingStrategyType || (Measurement.TimingStrategyType = {}));
    function getTimingStrategy(type) {
        switch (type) {
            case TimingStrategyType.ClosestMatch:
                return new ClosestMatchStrategy();
            case TimingStrategyType.MaxMemoryMarch:
                return new MaxMemoryMarchStrategy();
            default:
                throw new Error("Unknown type.");
        }
    }
    Measurement.getTimingStrategy = getTimingStrategy;
    Measurement.defaultTimingStrategy = new Measurement.ClosestMatchStrategy();
    Measurement.defaultTimingOptions = {
        type: exports.argon2i,
        maxTimeMs: 100,
        plain: "this is a super cool password",
        saltLength: 16,
        statusCallback: function statusCallback(t) {
            var ms = "Hashed in " + t.computeTimeMs + "ms.";
            var hc = "Cost: " + t.hashCost + ".";
            var pc = "P: " + t.options.parallelism + ".";
            var mc = "M: " + t.options.memoryCost + " (" + Math.pow(2, t.options.memoryCost) / 1024 + "MB).";
            var tc = "T: " + t.options.timeCost + ".";
            console.log(ms + " " + hc + " " + pc + " " + mc + " " + tc);
            return true;
        }
    };
    function generateTimings(options, timingStrategy) {
        timingStrategy = timingStrategy || Measurement.defaultTimingStrategy;
        options = _.extend({}, Measurement.defaultTimingOptions, options);
        return timingStrategy.run(options);
    }
    Measurement.generateTimings = generateTimings;
})(Measurement = exports.Measurement || (exports.Measurement = {}));
var Selection;
(function (Selection) {
    var LinearSelectionStrategy = function () {
        function LinearSelectionStrategy() {
            (0, _classCallCheck3.default)(this, LinearSelectionStrategy);

            this.timingsCache = {};
        }

        (0, _createClass3.default)(LinearSelectionStrategy, [{
            key: "initialize",
            value: function initialize(timingResults) {
                if (!timingResults || !timingResults.timings || !timingResults.timings.length) {
                    throw new Error("Argument error. No timings found.");
                }
                // Sort timings by memory and then elapsed ms
                // So the most memory expensive things will be first for selection
                this.sortedTimings = this.getSortedTimings(timingResults.timings);
                var computeTimeList = _.sortBy(timingResults.timings, "computeTimeMs");
                this.fastestTiming = _.head(computeTimeList);
                this.slowestTiming = _.last(computeTimeList);
            }
        }, {
            key: "select",
            value: function select(maxTimeMs) {
                var timing = this.timingsCache[maxTimeMs] || _.findLast(this.sortedTimings, function (timing) {
                    return timing.computeTimeMs <= maxTimeMs;
                });
                // No options available...
                if (!timing) {
                    return this.fastest();
                }
                this.timingsCache[maxTimeMs] = timing;
                return timing;
            }
        }, {
            key: "fastest",
            value: function fastest() {
                return this.fastestTiming;
            }
        }, {
            key: "slowest",
            value: function slowest() {
                return this.slowestTiming;
            }
        }]);
        return LinearSelectionStrategy;
    }();

    Selection.LinearSelectionStrategy = LinearSelectionStrategy;

    var MaxCostSelectionStrategy = function (_LinearSelectionStrat) {
        (0, _inherits3.default)(MaxCostSelectionStrategy, _LinearSelectionStrat);

        function MaxCostSelectionStrategy() {
            (0, _classCallCheck3.default)(this, MaxCostSelectionStrategy);

            var _this3 = (0, _possibleConstructorReturn3.default)(this, (MaxCostSelectionStrategy.__proto__ || Object.getPrototypeOf(MaxCostSelectionStrategy)).apply(this, arguments));

            _this3.name = "maxcost";
            return _this3;
        }

        (0, _createClass3.default)(MaxCostSelectionStrategy, [{
            key: "getSortedTimings",
            value: function getSortedTimings(timings) {
                return _.orderBy(timings, ["hashCost", "computeTimeMs"], ["asc", "asc"]);
            }
        }]);
        return MaxCostSelectionStrategy;
    }(LinearSelectionStrategy);

    Selection.MaxCostSelectionStrategy = MaxCostSelectionStrategy;

    var ClosestMatchSelectionStrategy = function (_LinearSelectionStrat2) {
        (0, _inherits3.default)(ClosestMatchSelectionStrategy, _LinearSelectionStrat2);

        function ClosestMatchSelectionStrategy() {
            (0, _classCallCheck3.default)(this, ClosestMatchSelectionStrategy);

            var _this4 = (0, _possibleConstructorReturn3.default)(this, (ClosestMatchSelectionStrategy.__proto__ || Object.getPrototypeOf(ClosestMatchSelectionStrategy)).apply(this, arguments));

            _this4.name = "closestmatch";
            return _this4;
        }

        (0, _createClass3.default)(ClosestMatchSelectionStrategy, [{
            key: "getSortedTimings",
            value: function getSortedTimings(timings) {
                return _.sortBy(timings, "computeTimeMs");
            }
        }]);
        return ClosestMatchSelectionStrategy;
    }(LinearSelectionStrategy);

    Selection.ClosestMatchSelectionStrategy = ClosestMatchSelectionStrategy;
    var SelectionStrategyType = void 0;
    (function (SelectionStrategyType) {
        SelectionStrategyType[SelectionStrategyType["MaxCost"] = 0] = "MaxCost";
        SelectionStrategyType[SelectionStrategyType["ClosestMatch"] = 1] = "ClosestMatch";
    })(SelectionStrategyType = Selection.SelectionStrategyType || (Selection.SelectionStrategyType = {}));
    function getSelectionStrategy(type) {
        switch (type) {
            case SelectionStrategyType.ClosestMatch:
                return new ClosestMatchSelectionStrategy();
            case SelectionStrategyType.MaxCost:
                return new MaxCostSelectionStrategy();
            default:
                throw new Error("Unknown type.");
        }
    }
    Selection.getSelectionStrategy = getSelectionStrategy;
})(Selection = exports.Selection || (exports.Selection = {}));
var TimingStrategyType = Measurement.TimingStrategyType;
var SelectionStrategyType = Selection.SelectionStrategyType;
var optionsCache = {};
function optionsCacheKey() {
    var maxMs = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : Measurement.defaultTimingOptions.maxTimeMs;
    var timingStrategy = arguments[1];
    var selectionStrategy = arguments[2];

    return maxMs + ":" + timingStrategy + ":" + selectionStrategy;
}
function getMaxOptionsWithStrategies() {
    var maxMs = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : Measurement.defaultTimingOptions.maxTimeMs;
    var timingStrategy = arguments[1];
    var selectionStrategy = arguments[2];

    return __awaiter(this, void 0, void 0, /*#__PURE__*/_regenerator2.default.mark(function _callee2() {
        var cacheKey, options, timings, selectedTiming;
        return _regenerator2.default.wrap(function _callee2$(_context2) {
            while (1) {
                switch (_context2.prev = _context2.next) {
                    case 0:
                        cacheKey = optionsCacheKey(maxMs, timingStrategy.name, selectionStrategy.name);
                        options = optionsCache[cacheKey];

                        if (!options) {
                            _context2.next = 4;
                            break;
                        }

                        return _context2.abrupt("return", options);

                    case 4:
                        _context2.next = 6;
                        return Measurement.generateTimings({ maxTimeMs: maxMs }, timingStrategy);

                    case 6:
                        timings = _context2.sent;

                        selectionStrategy.initialize(timings);
                        selectedTiming = selectionStrategy.select(maxMs);

                        optionsCache[cacheKey] = options = selectedTiming.options;
                        return _context2.abrupt("return", options);

                    case 11:
                    case "end":
                        return _context2.stop();
                }
            }
        }, _callee2, this);
    }));
}
exports.getMaxOptionsWithStrategies = getMaxOptionsWithStrategies;
function getMaxOptions() {
    var maxMs = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : Measurement.defaultTimingOptions.maxTimeMs;
    var timingStrategy = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : TimingStrategyType.ClosestMatch;
    var selectionStrategy = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : SelectionStrategyType.MaxCost;

    return __awaiter(this, void 0, void 0, /*#__PURE__*/_regenerator2.default.mark(function _callee3() {
        return _regenerator2.default.wrap(function _callee3$(_context3) {
            while (1) {
                switch (_context3.prev = _context3.next) {
                    case 0:
                        return _context3.abrupt("return", getMaxOptionsWithStrategies(maxMs, Measurement.getTimingStrategy(timingStrategy), Selection.getSelectionStrategy(selectionStrategy)));

                    case 1:
                    case "end":
                        return _context3.stop();
                }
            }
        }, _callee3, this);
    }));
}
exports.getMaxOptions = getMaxOptions;