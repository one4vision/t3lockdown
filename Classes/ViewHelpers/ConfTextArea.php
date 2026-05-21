<?php
namespace Extension14v\T3lockdown\ViewHelpers;

use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3Fluid\Fluid\Core\ViewHelper\TagBuilder;

class ConfTextArea
{
    /**
     * @var TagBuilder
     */
    protected TagBuilder $tag;

    public function __construct() {
        $this->tag = GeneralUtility::makeInstance(TagBuilder::class);
    }

    public function render(array $parameter = []): string
    {
        $value = $GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS']['t3lockdown'][$parameter['fieldName']];
        $this->tag->setTagName('textarea');
        $this->tag->forceClosingTag(true);
        $this->tag->addAttribute('cols', 40);
        $this->tag->addAttribute('rows', 5);
        $this->tag->addAttribute('name', $parameter['fieldName']);
        $this->tag->addAttribute('id', 'em-t3lockdown-'.$parameter['fieldName']);
        $this->tag->addAttribute('class', 'form-control');
        $this->tag->setContent(trim((string) $value));
        return $this->tag->render();
    }
}