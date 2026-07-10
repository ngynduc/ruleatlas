import {
  Button,
  Dialog,
  DialogHeader,
  HStack,
  Layout,
  LayoutContent,
  LayoutFooter,
} from '@astryxdesign/core';

interface JsonModalProps {
  title: string;
  value: unknown;
  onClose: () => void;
  onCopy: (json: string) => Promise<void> | void;
}

export function JsonModal({ title, value, onClose, onCopy }: JsonModalProps) {
  const json = JSON.stringify(value, null, 2);

  return (
    <Dialog
      isOpen
      maxHeight="calc(100dvh - 32px)"
      purpose="info"
      width="min(980px, calc(100vw - 32px))"
      onOpenChange={(isOpen) => {
        if (!isOpen) {
          onClose();
        }
      }}
    >
      <Layout
        height="auto"
        header={<DialogHeader hasDivider title={title} subtitle="JSON preview" onOpenChange={onClose} />}
        footer={
          <LayoutFooter hasDivider label="JSON actions">
            <HStack gap={2} justify="end" padding={3}>
              <Button label="Copy JSON" variant="secondary" onClick={() => onCopy(json)} />
              <Button label="Close" variant="primary" onClick={onClose} />
            </HStack>
          </LayoutFooter>
        }
      >
        <LayoutContent label={`${title} JSON`}>
          <pre className="json-preview">{json}</pre>
        </LayoutContent>
      </Layout>
    </Dialog>
  );
}
