<?php
namespace Extension14v\T3lockdown\Domain\Repository;

use Extension14v\T3lockdown\Domain\Model\Attempts;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Extbase\Persistence\QueryInterface;
use TYPO3\CMS\Extbase\Persistence\Repository;

class AttemptsRepository extends Repository
{
    public function findAllForBackend() {
        $query = $this->createQuery();
        $query->setOrderings([
            'uid' => QueryInterface::ORDER_DESCENDING,
        ]);
        $query->getQuerySettings()->setRespectStoragePage(false);
        return $query->execute();
    }

    public function modifyAttempts($attempts) {
        foreach($attempts as $attempt) {
            /** @var Attempts $attempt */
            $details = $attempt->getDetails();
            $encodedDetails = base64_encode($details);
            $attempt->setEncodedDetails($encodedDetails);
        }
        return $attempts;
    }

    public function buildResultDataset($attempts): array {
        $sql = 0;
        $xss = 0;
        $header = 0;
        $methods = [];
        $dates = [];

        foreach($attempts as $attempt) {
            /** @var Attempts $attempt */

            // DATE
            $d = $attempt->getAttackDate()->format('d');
            $m = $attempt->getAttackDate()->format('m');
            $Y = $attempt->getAttackDate()->format('Y');

            if(!array_key_exists($Y, $dates)) {
                $dates[$Y] = ['sum' => 1, 'months' => []];
            } else {
                $dates[$Y]['sum']++;
            }
            if(!array_key_exists($m, $dates[$Y]['months'])) {
                $dates[$Y]['months'][$m] = ['sum' => 1, 'days' => []];
            } else {
                $dates[$Y]['months'][$m]['sum']++;
            }
            if(!array_key_exists($d, $dates[$Y]['months'][$m]['days'])) {
                $dates[$Y]['months'][$m]['days'][$d] = 1;
            } else {
                $dates[$Y]['months'][$m]['days'][$d]++;
            }

            // METHOD
            if(!array_key_exists($attempt->getRequestMethod(), $methods)) {
                $methods[$attempt->getRequestMethod()] = 0;
            }
            $methods[$attempt->getRequestMethod()]++;

            // HEADER
            if($attempt->getFromHeader() === 1) {
                $header++;
            }

            // TYPES
            $attackTypes = GeneralUtility::trimExplode(',', $attempt->getAttackTypes(), true);
            foreach($attackTypes as $attackType) {
                if($attackType === 'sql') {
                    $sql++;
                }
                if($attackType === 'xss') {
                    $xss++;
                }
            }
        }
        return [
            'sql' => $sql,
            'xss' => $xss,
            'header' => $header,
            'methods' => $methods,
            'dates' => $dates
        ];
    }

    public function buildChartData(array $dataset): string {
        $result = [];
        $temp = [];
        $dates = $dataset['dates'] ?: [];
        foreach($dates as $year => $data) {
            $months = $data['months'] ?: [];
            foreach($months as $month => $monthData) {
                $label = $year.'-'.$month;
                $temp[$label] = $monthData['sum'];
            }
        }
        $current = new \DateTimeImmutable('first day of this month');
        for($i=0; $i<12; $i++) {
            $label = $current->format('m / Y');
            $tempLabel = $current->format('Y-m');
            $result[] = [
                'label' => $label,
                'y' => $temp[$tempLabel] ?? 0
            ];
            $current = $current->sub(new \DateInterval('P1M'));
        }
        return json_encode($result);
    }
}
