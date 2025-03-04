import { useCallback, useEffect, useState } from 'react';
import * as DropdownMenu from '@radix-ui/react-dropdown-menu';
import rawYamlData from './mock-data.yml';
import './HypothesisBuilder.css';

interface TreeNode {
  id: string;
  label: string;
  children: TreeNode[];
}

interface YamlData {
  [key: string]: YamlData | YamlData[] | string[];
}

export default function HypothesisBuilder() {
  const [treeData, setTreeData] = useState<TreeNode[]>([]);
  const [isDarkMode, setIsDarkMode] = useState<boolean>(false);

  // Check for dark mode preference
  useEffect(() => {
    // Check initial preference
    const darkModeQuery = window.matchMedia('(prefers-color-scheme: dark)');
    setIsDarkMode(darkModeQuery.matches);

    // Add listener for changes
    const listener = (e: MediaQueryListEvent) => {
      setIsDarkMode(e.matches);
    };
    
    darkModeQuery.addEventListener('change', listener);
    
    // Clean up
    return () => {
      darkModeQuery.removeEventListener('change', listener);
    };
  }, []);

  // Convert YAML data to tree structure
  const buildTree = useCallback((data: YamlData, parentId?: string): TreeNode[] => {
    return Object.entries(data).map(([key, value]) => {
      const nodeId = parentId ? `${parentId}-${key}` : key;
      const node: TreeNode = {
        id: nodeId,
        label: key,
        children: []
      };

      if (Array.isArray(value)) {
        node.children = value.map(item => {
          if (typeof item === 'string') {
            return {
              id: `${nodeId}-${item}`,
              label: item,
              children: []
            };
          } else {
            return buildTree(item as YamlData, nodeId)[0];
          }
        });
      } else if (value && typeof value === 'object') {
        node.children = buildTree(value as YamlData, nodeId);
      }

      return node;
    });
  }, []);

  // Initialize tree data
  useEffect(() => {
    try {
      const tree = buildTree(rawYamlData as unknown as YamlData);
      setTreeData(tree);
    } catch (error) {
      console.error('Error parsing YAML:', error);
    }
  }, [buildTree]);

  // Recursive function to render menu items
  const renderDropdownMenuItems = (nodes: TreeNode[]) => {
    return nodes.map((node) => {
      if (node.children.length === 0) {
        // Leaf node - render as a simple item
        return (
          <DropdownMenu.Item 
            key={node.id} 
            className="DropdownMenuItem"
            onSelect={() => console.log(`Selected: ${node.label}`)}
          >
            {node.label}
          </DropdownMenu.Item>
        );
      } else {
        // Node with children - render as a submenu
        return (
          <DropdownMenu.Sub key={node.id}>
            <DropdownMenu.SubTrigger className="DropdownMenuSubTrigger">
              {node.label}
              <div className="RightSlot">
                <span className="ChevronRight">▶</span>
              </div>
            </DropdownMenu.SubTrigger>
            <DropdownMenu.Portal>
              <DropdownMenu.SubContent 
                className="DropdownMenuSubContent"
                sideOffset={2}
                alignOffset={-5}
              >
                {renderDropdownMenuItems(node.children)}
              </DropdownMenu.SubContent>
            </DropdownMenu.Portal>
          </DropdownMenu.Sub>
        );
      }
    });
  };

  // Render root level nodes as individual dropdown menus
  const renderRootMenus = () => {
    return treeData.map((rootNode) => (
      <div key={rootNode.id} className="MenuWrapper">
        <DropdownMenu.Root>
          <DropdownMenu.Trigger asChild>
            <button className="MenuButton">
              {rootNode.label} <span className="DownArrow">▼</span>
            </button>
          </DropdownMenu.Trigger>

          <DropdownMenu.Portal>
            <DropdownMenu.Content className="DropdownMenuContent" sideOffset={5}>
              {renderDropdownMenuItems(rootNode.children)}
              <DropdownMenu.Arrow className="DropdownMenuArrow" />
            </DropdownMenu.Content>
          </DropdownMenu.Portal>
        </DropdownMenu.Root>
      </div>
    ));
  };

  return (
    <div className={`HypothesisBuilderContainer ${isDarkMode ? 'dark-mode' : 'light-mode'}`}>
      <h1>Hypothesis Builder</h1>
      <div className="MenuContainer">
        {renderRootMenus()}
      </div>
    </div>
  );
}
