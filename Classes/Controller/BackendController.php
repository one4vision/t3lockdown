<?php
namespace Extension14v\T3lockdown\Controller;

use Extension14v\T3lockdown\Domain\Repository\AttemptsRepository;
use Psr\Http\Message\ResponseInterface;
use TYPO3\CMS\Backend\Module\ModuleData;
use TYPO3\CMS\Backend\Template\Components\ButtonBar;
use TYPO3\CMS\Backend\Template\ModuleTemplate;
use TYPO3\CMS\Backend\Template\ModuleTemplateFactory;
use TYPO3\CMS\Core\Imaging\Icon;
use TYPO3\CMS\Core\Imaging\IconFactory;
use TYPO3\CMS\Core\Information\Typo3Version;
use TYPO3\CMS\Core\Page\PageRenderer;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Extbase\Configuration\ConfigurationManagerInterface;
use TYPO3\CMS\Extbase\Mvc\Controller\ActionController;

/***
 *
 * This file is part of the "Imagecredits14v" Extension for TYPO3 CMS.
 *
 * For the full copyright and license information, please read the
 * LICENSE.txt file that was distributed with this source code.
 *
 *  (c) 2019 Oliver Busch <ob@14v.de>, one4vision GmbH
 *
 ***/

/**
 * BackendController
 */
class BackendController extends ActionController
{
    protected ?ModuleData $moduleData = null;
    protected ModuleTemplate $moduleTemplate;
    protected ModuleTemplateFactory $moduleTemplateFactory;
    protected IconFactory $iconFactory;
    protected PageRenderer $pageRenderer;
    protected AttemptsRepository $attemptsRepository;
    protected int $t3v = 13;

    public function injectModuleTemplateFactory(ModuleTemplateFactory $moduleTemplateFactory): void
    {
        $this->moduleTemplateFactory = $moduleTemplateFactory;
    }

    public function injectIconFactory(IconFactory $iconFactory): void
    {
        $this->iconFactory = $iconFactory;
    }

    public function injectPageRenderer(PageRenderer $pageRenderer): void
    {
        $this->pageRenderer = $pageRenderer;
    }

    public function injectAttemptsRepository(AttemptsRepository $attemptsRepository): void {
        $this->attemptsRepository = $attemptsRepository;
    }

    public function initializeAction(): void
    {
        $this->settings = $this->configurationManager->getConfiguration(
            ConfigurationManagerInterface::CONFIGURATION_TYPE_SETTINGS
        );

        $this->moduleData = $this->request->getAttribute('moduleData');
        $this->moduleTemplate = $this->moduleTemplateFactory->create($this->request);
        $this->moduleTemplate->setFlashMessageQueue($this->getFlashMessageQueue());

        $t3Version = GeneralUtility::makeInstance(Typo3Version::class);
        $this->t3v = $t3Version->getMajorVersion();
    }

    /**
     * action list
     */
    public function listAction(): ResponseInterface
    {
        $this->pageRenderer->loadJavaScriptModule('@extension14v/t3lockdown/AttackModal.js');
        $this->pageRenderer->loadJavaScriptModule('@extension14v/t3lockdown/TableFilter.js');

        $attempts = $this->attemptsRepository->findAllForBackend();
        $attempts = $this->attemptsRepository->modifyAttempts($attempts);
        $dataset = $this->attemptsRepository->buildResultDataset($attempts);
        $chartData = $this->attemptsRepository->buildChartData($dataset);
        $this->moduleTemplate->assignMultiple([
            'attempts' => $attempts,
            'dataset' => $dataset,
            'chartData' => base64_encode($chartData)
        ]);

        $this->moduleTemplate->setTitle('T3Lockdown');
        $this->addButtons();
        return $this->moduleTemplate->renderResponse('Backend/List');
    }

    protected function addButtons(): void
    {
        $buttonBar = $this->moduleTemplate->getDocHeaderComponent()->getButtonBar();
        $requestUri = $this->request->getUri();

        if($this->t3v < 14) {
            // Reload
            $reloadButton = $buttonBar->makeLinkButton()
                ->setHref($requestUri)
                ->setTitle('Reload')
                ->setIcon($this->iconFactory->getIcon('actions-refresh', Icon::SIZE_SMALL));
            $buttonBar->addButton($reloadButton, ButtonBar::BUTTON_POSITION_RIGHT);
        }

        // Shortcut
        $shortcutButton = $buttonBar->makeShortcutButton()
            ->setRouteIdentifier('site_t3lockdown')
            ->setDisplayName('Shortcut');
        $buttonBar->addButton($shortcutButton, ButtonBar::BUTTON_POSITION_RIGHT);

    }
}
