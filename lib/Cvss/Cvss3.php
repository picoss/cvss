<?php

namespace Picoss\Cvss;

use Symfony\Component\OptionsResolver\Options;
use Symfony\Component\OptionsResolver\OptionsResolver;

class Cvss3
{

    /**
     * CVSS Version
     */
    const VERSION = '3.0';

    /**
     * @var string
     */
    static private $vectorHead = 'CVSS:3.0';

    /**
     * @var string
     */
    static private $metricSeparator = '/';

    /**
     * @var string
     */
    static private $valueSeparator = ':';

    /**
     * @var array
     */
    private $vectorInputs = [];

    /**
     * @var array
     */
    private $vectorLevels = [];

    /**
     * @var float
     */
    private $baseScore;

    /**
     * @var float
     */
    private $temporalScore;

    /**
     * @var float
     */
    private $environmentalScore;

    /**
     * Base metrics definition
     *
     * @var array
     */
    private $baseMetrics = array(
        'AV' => array(
            'N' => 0.85,
            'A' => 0.62,
            'L' => 0.55,
            'P' => 0.2,
        ),
        'AC' => array(
            'L' => 0.77,
            'H' => 0.44,
        ),
        'PR' => array(
            'N' => 0.85,
            'L' => array(
                'unchanged' => 0.62,
                'changed' => 0.68,
            ),
            'H' => array(
                'unchanged' => 0.27,
                'changed' => 0.50,
            ),
        ),
        'UI' => array(
            'N' => 0.85,
            'R' => 0.62,
        ),
        'S' => array(
            'U' => 0,
            'C' => 0,
        ),
        'C' => array(
            'H' => 0.56,
            'L' => 0.22,
            'N' => 0,
        ),
        'I' => array(
            'H' => 0.56,
            'L' => 0.22,
            'N' => 0,
        ),
        'A' => array(
            'H' => 0.56,
            'L' => 0.22,
            'N' => 0,
        ),
    );

    /**
     * Temporal metrics definition
     *
     * @var array
     */
    private $temporalMetrics = array(
        'E' => array(
            'X' => 1,
            'U' => 0.91,
            'P' => 0.94,
            'F' => 0.97,
            'H' => 1,
        ),
        'RL' => array(
            'X' => 1,
            'O' => 0.95,
            'T' => 0.96,
            'W' => 0.97,
            'U' => 1,
        ),
        'RC' => array(
            'X' => 1,
            'U' => 0.92,
            'R' => 0.96,
            'C' => 1,
        ),
    );

    /**
     * Environment metrics definition
     *
     * @var array
     */
    private $environmentalMetrics = array(
        'CR' => array(
            'X' => 1,
            'L' => 0.5,
            'M' => 1,
            'H' => 1.5,
        ),
        'IR' => array(
            'X' => 1,
            'L' => 0.5,
            'M' => 1,
            'H' => 1.5,
        ),
        'AR' => array(
            'X' => 1,
            'L' => 0.5,
            'M' => 1,
            'H' => 1.5,
        ),
        'MAV' => array(
            'X' => 0,
            'N' => 0.85,
            'A' => 0.62,
            'L' => 0.55,
            'P' => 0.2,
        ),
        'MAC' => array(
            'X' => 0,
            'L' => 0.77,
            'H' => 0.44,
        ),
        'MPR' => array(
            'X' => 0,
            'N' => 0.85,
            'L' => array(
                'unchanged' => 0.62,
                'changed' => 0.68,
            ),
            'H' => array(
                'unchanged' => 0.27,
                'changed' => 0.50,
            ),
        ),
        'MUI' => array(
            'X' => 0,
            'N' => 0.85,
            'R' => 0.62,
        ),
        'MS' => array(
            'X' => 0,
            'U' => 0,
            'C' => 0,
        ),
        'MC' => array(
            'X' => 0,
            'N' => 0,
            'L' => 0.22,
            'H' => 0.56,
        ),
        'MI' => array(
            'X' => 0,
            'N' => 0,
            'L' => 0.22,
            'H' => 0.56,
        ),
        'MA' => array(
            'X' => 0,
            'N' => 0,
            'L' => 0.22,
            'H' => 0.56,
        ),
    );

    /**
     * Severity rating scale
     *
     * @var array
     */
    private $severityRatingScale = array(
        'N' => array(
            'min_range' => 0,
            'max_range' => 0.1,
        ),
        'L' => array(
            'min_range' => 0.1,
            'max_range' => 3.9,
        ),
        'M' => array(
            'min_range' => 4.0,
            'max_range' => 6.9,
        ),
        'H' => array(
            'min_range' => 7.0,
            'max_range' => 8.9,
        ),
        'C' => array(
            'min_range' => 9.0,
            'max_range' => 10.0,
        ),
    );

    public function __construct()
    {

    }

    /**
     * Parse CVSS vector
     *
     * @param string $vector
     *
     * @throws \InvalidArgumentException
     */
    public function setVector($vector)
    {
        if (empty($vector)) {
            throw new \InvalidArgumentException(sprintf('Cvss vector "%s" is not valid.', $vector));
        }

        if (!preg_match('/^' . self::$vectorHead . '.*/mi', $vector)) {
            throw new \InvalidArgumentException((sprintf('Cvss vector "%s" is not valid. Must start with "%s"', $vector, self::$vectorHead)));
        }

        $this->vectorInputs = self::parseVector($vector);

        $resolver = $this->getInputLevelConfiguration();
        $this->vectorLevels = $resolver->resolve($this->vectorInputs);

        $this->calculate();
    }

    /**
     * Get base CVSS score
     *
     * @return float
     */
    public function getBaseScore()
    {
        return $this->baseScore;
    }

    /**
     * Get base score severity
     *
     * @return int|null|string
     */
    public function getBaseScoreSeverity()
    {
        return $this->getSeverity($this->baseScore);
    }

    /**
     * Get base metric definitions
     *
     * @return array
     */
    public function getBaseMetricDefinitions()
    {
        return $this->baseMetrics;
    }

    /**
     * Get temporal score
     *
     * @return float
     */
    public function getTemporalScore()
    {
        return $this->temporalScore;
    }

    /**
     * Get temporal score severity
     *
     * @return int|null|string
     */
    public function getTemporalScoreSeverity()
    {
        return $this->getSeverity($this->temporalScore);
    }

    /**
     * Get temporal metric definitions
     *
     * @return array
     */
    public function getTemporalMetricDefinitions()
    {
        return $this->temporalMetrics;
    }

    /**
     * Get environmental score
     *
     * @return float
     */
    public function getEnvironmentalScore()
    {
        return $this->environmentalScore;
    }

    /**
     * Get environmental score severity
     *
     * @return null|string
     */
    public function getEnvironmentalScoreSeverity()
    {
        return $this->getSeverity($this->environmentalScore);
    }

    /**
     * Get environmental metric definitions
     *
     * @return array
     */
    public function getEnvironmentalMetricDefinitions()
    {
        return $this->environmentalMetrics;
    }

    /**
     * Get severity for the given score
     *
     * @param float $score
     *
     * @return int|null|string
     */
    protected function getSeverity($score)
    {
        foreach ($this->severityRatingScale as $level => $options) {
            if ($score >= $options['min_range'] && $score <= $options['max_range']) {
                return $level;
            }
        }
        return null;
    }

    /**
     * Get base vector
     *
     * @return string
     */
    public function getBaseVector()
    {
        return self::buildVector(array_intersect_key($this->vectorInputs, $this->baseMetrics));
    }

    /**
     * Get full vector
     *
     * @param bool $omitUndefined Do not include metrics that are not defined (ex:MPR:X)
     *
     * @return string
     */
    public function getVector($omitUndefined = true)
    {
        $metrics = [];
        foreach ($this->vectorInputs as $name => $value) {
            if ($value != 'X' || !$omitUndefined) {
                $metrics[$name] = $value;
            }
        }

        return self::buildVector($metrics);
    }

    /**
     * Build CVSS vector for the given inputs
     *
     * @param array $inputs
     *
     * @return string
     */
    static function buildVector($inputs)
    {
        $inputs = array_merge(array('CVSS' => self::VERSION), $inputs);
        return implode(self::$metricSeparator, array_map(function ($k, $v) {
            return sprintf('%1$s%3$s%2$s', strtoupper($k), strtoupper($v), self::$valueSeparator);
        }, array_keys($inputs), $inputs));
    }

    /**
     * Parse vector
     *
     * @param string $vector
     *
     * @return array
     */
    static function parseVector($vector)
    {
        $vectorInputs = array();
        $vector = preg_replace('/^' . self::$vectorHead . '[\\' . self::$metricSeparator . ']?/', '', $vector);
        $metrics = explode(self::$metricSeparator, $vector);
        if (count($metrics)) {
            foreach ($metrics as $metric) {
                if (!empty($metric)) {
                    list($name, $value) = explode(self::$valueSeparator, $metric);
                    $vectorInputs[$name] = $value;
                }
            }
        }
        return $vectorInputs;
    }

    /**
     * Use OptionResolver to get input level configuration
     *
     * @return OptionsResolver
     */
    private function getInputLevelConfiguration()
    {
        $resolver = new OptionsResolver();
        foreach ($this->baseMetrics as $metric => $values) {
            $resolver
                ->setRequired($metric)
                ->setAllowedValues($metric, array_keys($values))
            ;
            if ($metric == 'PR') {
                $resolver->setNormalizer($metric, function (Options $options, $value) use ($metric) {
                    switch ($value) {
                        case 'L':
                        case 'H':
                            if ($options['S'] == 'U') {
                                $value = (float) $this->baseMetrics[$metric][$value]['unchanged'];
                            }
                            elseif ($options['S'] == 'C') {
                                $value = (float) $this->baseMetrics[$metric][$value]['changed'];
                            }
                            break;
                        default:
                            $value = (float) $this->baseMetrics[$metric][$value];
                            break;
                    }
                    return $value;
                });
            }
            elseif ($metric != 'S') {
                $resolver->setNormalizer($metric, function (Options $options, $value) use ($metric) {
                    return (float) $this->baseMetrics[$metric][$value];
                });
            }
        }

        foreach ($this->temporalMetrics as $metric => $values) {
            $resolver
                ->setDefault($metric, 'X')
                ->setAllowedValues($metric, array_keys($values))
                ->setNormalizer($metric, function (Options $options, $value) use ($metric) {
                    return (float) $this->temporalMetrics[$metric][$value];
                })
            ;
        }

        foreach ($this->environmentalMetrics as $metric => $values) {
            $resolver
                ->setDefault($metric, 'X')
                ->setAllowedValues($metric, array_keys($values))
            ;
            switch ($metric) {
                case 'MS': break;
                case 'MPR':
                    $resolver->setNormalizer($metric, function (Options $options, $value) use ($metric) {
                        $modifiedScope = $options['MS'] != 'X' ? $options['MS'] : $options['S'];
                        switch ($value) {
                            case 'X':
                                switch ($modifiedScope) {
                                    case 'U':
                                        $value = (float) $this->baseMetrics[substr($metric, 1)][$this->vectorInputs[substr($metric, 1)]]['unchanged'];
                                        break;
                                    case 'C':
                                        $value = (float) $this->baseMetrics[substr($metric, 1)][$this->vectorInputs[substr($metric, 1)]]['changed'];
                                        break;
                                }
                                break;
                            case 'L':
                            case 'H':
                                switch ($modifiedScope) {
                                    case 'U':
                                        $value = (float) $this->environmentalMetrics[$metric][$value]['unchanged'];
                                        break;
                                    case 'C':
                                        $value = (float) $this->environmentalMetrics[$metric][$value]['changed'];
                                        break;
                                }
                                break;
                            default:
                                $value = (float) $this->environmentalMetrics[$metric][$value];
                                break;
                        }

                        return $value;
                    });
                    break;
                case 'CR':
                case 'IR':
                case 'AR':
                    $resolver->setNormalizer($metric, function (Options $options, $value) use ($metric) {
                        return (float) $this->environmentalMetrics[$metric][$value];
                    });
                    break;
                default:
                    $resolver->setNormalizer($metric, function (Options $options, $value) use ($metric) {
                        if ($value == 'X') {
                            $value = (float) $options[substr($metric, 1)];
                        }
                        else {
                            $value = (float) $this->environmentalMetrics[$metric][$value];
                        }
                        return $value;
                    });
                    break;
            }
        }

        return $resolver;
    }

    /**
     * Calculate base, temporal and environmental scores
     */
    private function calculate()
    {
        /**
         * Base score
         */
        $impactSubScore = 0;
        $impactSubScoreBase = 1 - ((1 - $this->vectorLevels['C']) * (1 - $this->vectorLevels['I']) * (1 - $this->vectorLevels['A']));
        switch ($this->vectorLevels['S']) {
            case 'U':
                $impactSubScore = 6.42 * $impactSubScoreBase;
                break;
            case 'C':
                $impactSubScore = 7.52 * ($impactSubScoreBase - 0.029) - 3.25 * pow(($impactSubScoreBase - 0.02), 15);
                break;
        }

        $exploitabilitySubScore = 8.22 * $this->vectorLevels['AV'] * $this->vectorLevels['AC'] * $this->vectorLevels['PR'] * $this->vectorLevels['UI'];

        if ($impactSubScore <= 0) {
            $this->baseScore = 0;
        }
        else {
            switch ($this->vectorLevels['S']) {
                case 'U':
                    $this->baseScore = self::roundUp(min($impactSubScore + $exploitabilitySubScore, 10));
                    break;
                case 'C':
                    $this->baseScore = self::roundUp(min(1.08 * ($impactSubScore + $exploitabilitySubScore), 10));
                    break;
            }
        }

        /**
         * Temporal score
         */
        $this->temporalScore = self::roundUp($this->baseScore * $this->vectorLevels['E'] * $this->vectorLevels['RL'] * $this->vectorLevels['RC']);

        /**
         * Environmental score
         */
        $modifiedImpactSubScore = 0;
        $modifiedImpactSubScoreBase = min(1 - ((1 - $this->vectorLevels['MC'] * $this->vectorLevels['CR']) * (1 - $this->vectorLevels['MI'] * $this->vectorLevels['IR']) * (1 - $this->vectorLevels['MA'] * $this->vectorLevels['AR'])), 0.915);
        $modifiedScope = $this->vectorLevels['MS'] != 'X' ? $this->vectorLevels['MS'] : $this->vectorLevels['S'];
        switch ($modifiedScope) {
            case 'U':
                $modifiedImpactSubScore = 6.42 * $modifiedImpactSubScoreBase;
                break;
            case 'C':
                $modifiedImpactSubScore = 7.52 * ($modifiedImpactSubScoreBase - 0.029) - 3.25 * pow(($modifiedImpactSubScoreBase - 0.02), 15);
                break;
        }

        $modifiedExploitabilitySubScore = 8.22 * $this->vectorLevels['MAV'] * $this->vectorLevels['MAC'] * $this->vectorLevels['MPR'] * $this->vectorLevels['MUI'];

        if ($modifiedImpactSubScore <= 0) {
            $this->environmentalScore = $this->baseScore;
        }
        else {
            switch ($modifiedScope) {
                case 'U':
                    $this->environmentalScore = self::roundUp(self::roundUp(min($modifiedImpactSubScore + $modifiedExploitabilitySubScore, 10)) * $this->vectorLevels['E'] * $this->vectorLevels['RL'] * $this->vectorLevels['RC']);
                    break;
                case 'C':
                    $this->environmentalScore = self::roundUp(self::roundUp(min(1.08 * ($modifiedImpactSubScore + $modifiedExploitabilitySubScore), 10)) * $this->vectorLevels['E'] * $this->vectorLevels['RL'] * $this->vectorLevels['RC']);
                    break;
            }
        }
    }

    /**
     *
     * @param float $number number to round
     *
     * @return float
     */
    public static function roundUp($number)
    {
        return round(ceil($number * 10) / 10, 1);
    }
}