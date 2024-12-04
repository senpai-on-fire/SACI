import {
    CurveFactory,
    Edge,
    GeomEdge,
    GeomGraph,
    GeomNode,
    Graph,
    Node,
    Point,
    layoutGeomGraph,
} from 'https://cdn.jsdelivr.net/npm/@msagl/core@1.1.23/+esm';

// Mock data for CPVs and their details
const cpvs_blueprint_1 = [
    { id: 1, name: "CPV 1", details: ["Entry Component", "Required Component", "Associated CPS", "Initial System State", "Attack Vector", "Attack Impact", "Attack Requirements", "Privileges Requirements", "User-System Interactions", "Attack Steps"] },
    { id: 2, name: "CPV 2", details: ["Entry Component 2", "Required Component 2", "Associated CPS 2", "Initial System State 2", "Attack Vector 2", "Attack Impact 2", "Attack Requirements 2", "Privileges Requirements 2", "User-System Interactions 2", "Attack Steps 2"] },
];

let currentCPVId = null;
let autoUpdatePaused = false;
let selectedBlueprintId = null;

// Initialize blueprint selection handler
function initializeBlueprintSelection() {
    const blueprintSelect = document.getElementById("blueprint");
    if (blueprintSelect) {
        // Set initial value
        selectedBlueprintId = blueprintSelect.value;
        
        // Add change event listener
        blueprintSelect.addEventListener('change', function(e) {
            selectedBlueprintId = e.target.value;
            clearSearchResults();
            updateSearchButtonState();
            if (typeof get_blueprint_component_graph === 'function') {
                get_blueprint_component_graph(selectedBlueprintId);
            }
        });
    }
}

function clearSearchResults() {
    const cpvResultsDiv = document.getElementById("cpv-search-results");
    const cpvDetailsDiv = document.getElementById("cpv-detail-results");
    
    if (cpvResultsDiv) {
        cpvResultsDiv.innerHTML = '<div class="alert alert-info p-4 bg-blue-50 text-blue-700 rounded-md">Select a blueprint and click Search to find relevant CPVs.</div>';
    }
    
    if (cpvDetailsDiv) {
        cpvDetailsDiv.innerHTML = '';
    }
    
    currentCPVId = null;
}

function updateSearchButtonState() {
    const searchBtn = document.getElementById("search-btn");
    if (searchBtn) {
        if (selectedBlueprintId) {
            searchBtn.removeAttribute('disabled');
            searchBtn.title = 'Click to search for CPVs';
            searchBtn.classList.remove('opacity-50', 'cursor-not-allowed');
        } else {
            searchBtn.setAttribute('disabled', 'disabled');
            searchBtn.title = 'Please select a blueprint first';
            searchBtn.classList.add('opacity-50', 'cursor-not-allowed');
        }
    }
}

function searchForCPVs() {
    if (!selectedBlueprintId) {
        console.error("No blueprint selected");
        return;
    }

    console.log(`Searching CPVs for blueprint: ${selectedBlueprintId}`);

    autoUpdatePaused = true;
    setTimeout(() => {
        autoUpdatePaused = false;
    }, 10000);

    const cpvResultsDiv = document.getElementById("cpv-search-results");
    if (!cpvResultsDiv) {
        console.error("CPV results container not found");
        return;
    }

    cpvResultsDiv.innerHTML = '<div class="alert alert-info p-4 bg-blue-50 text-blue-700 rounded-md">Searching CPVs...</div>';

    const table = document.createElement("table");
    table.className = "min-w-full divide-y divide-gray-200 bg-white rounded-lg shadow-sm mt-4";
    
    const thead = document.createElement("thead");
    thead.className = "bg-gray-50";
    thead.innerHTML = `
        <tr>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">CPV ID</th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">CPV Name</th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Blueprint</th>
        </tr>
    `;
    table.appendChild(thead);

    const tbody = document.createElement("tbody");
    tbody.className = "bg-white divide-y divide-gray-200";

    cpvs_blueprint_1.forEach((cpv, index) => {
        const row = document.createElement("tr");
        row.className = index % 2 === 0 ? 'bg-white' : 'bg-gray-50';
        row.innerHTML = `
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${cpv.id}</td>
            <td class="px-6 py-4 whitespace-nowrap">
                <button 
                    onclick="window.showCPVDetails(${cpv.id})"
                    class="text-blue-600 hover:text-blue-900 text-sm font-medium"
                >${cpv.name}</button>
            </td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">Blueprint ${selectedBlueprintId}</td>
        `;
        tbody.appendChild(row);
    });

    table.appendChild(tbody);
    cpvResultsDiv.innerHTML = '';
    cpvResultsDiv.appendChild(table);
}

function showCPVDetails(cpvId) {
    console.log(`Displaying details for CPV ID: ${cpvId}`);
    currentCPVId = cpvId;

    const selectedCPV = cpvs_blueprint_1.find(cpv => cpv.id === cpvId);
    const cpvDetailDiv = document.getElementById("cpv-detail-results");

    if (!cpvDetailDiv) {
        console.error("CPV detail container not found");
        return;
    }

    // Create the interactive details view
    const detailsHTML = `
        <div class="bg-white p-6 rounded-lg shadow-sm">
            ${selectedCPV.details.map((detail, index) => `
                <div class="border-b last:border-b-0">
                    <button 
                        onclick="toggleDetail(${index})"
                        class="w-full px-4 py-3 text-left flex items-center justify-between hover:bg-gray-50 transition-colors"
                    >
                        <span class="font-medium text-gray-900">${detail}</span>
                        <svg class="w-5 h-5 text-gray-500 transform transition-transform detail-chevron-${index}" viewBox="0 0 20 20" fill="currentColor">
                            <path fill-rule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clip-rule="evenodd" />
                        </svg>
                    </button>
                    <div id="detail-content-${index}" class="hidden px-4 py-3 bg-gray-50">
                        <p class="text-sm text-gray-600">${getDetailDescription(detail)}</p>
                    </div>
                </div>
            `).join('')}
        </div>
    `;

    cpvDetailDiv.innerHTML = detailsHTML;
}

function getDetailDescription(detail) {
    // Add descriptions for each detail type
    const descriptions = {
        "Entry Component": "The point where an attacker initially gains access to the system",
        "Required Component": "System components that must be present for the vulnerability to be exploited",
        "Associated CPS": "Connected cyber-physical systems that could be affected",
        "Initial System State": "Required system conditions for the vulnerability to be present",
        "Attack Vector": "The method or path used to exploit the vulnerability",
        "Attack Impact": "The potential consequences of successful exploitation",
        "Attack Requirements": "Necessary conditions and resources for successful exploitation",
        "Privileges Requirements": "Access levels needed to exploit the vulnerability",
        "User-System Interactions": "Required interactions between users and the system",
        "Attack Steps": "Sequential steps involved in exploiting the vulnerability"
    };
    
    return descriptions[detail] || "Description not available";
}

function toggleDetail(index) {
    const content = document.getElementById(`detail-content-${index}`);
    const chevron = document.querySelector(`.detail-chevron-${index}`);
    
    if (content.classList.contains('hidden')) {
        content.classList.remove('hidden');
        chevron.style.transform = 'rotate(180deg)';
    } else {
        content.classList.add('hidden');
        chevron.style.transform = 'rotate(0)';
    }
}

function get_blueprint_component_graph(blueprint_id) {
    $("#blueprint_graph").empty();
    $("#blueprint_options").empty();
    $.ajax({
        url: "/api/get_blueprint",
        data: {
            "id": blueprint_id,
        },
        success: function (result) {
            if (result["error"] !== undefined) {
                console.log(result["error"]);
                return;
            }

            const data = result["component_graph"];
            const width = 1400;
            const height = 400; // Increased height for better spacing

            const svg = d3.select("#blueprint_graph")
                .append("svg")
                .attr("width", width)
                .attr("height", height);

            // Create force simulation
            const simulation = d3.forceSimulation(data.nodes)
                .force("link", d3.forceLink(data.links)
                    .id(d => d.id)
                    .distance(150)) // Increased link distance
                .force("charge", d3.forceManyBody()
                    .strength(-300)) // Increased repulsion
                .force("center", d3.forceCenter(width / 2, height / 2))
                .force("collision", d3.forceCollide().radius(50)); // Added collision detection

            // REMOVED: Original color scale
            // const color = d3.scaleOrdinal(d3.schemeCategory10);

            // Create container for graph elements with zoom capability
            const container = svg.append("g");
            
            // Add zoom behavior
            svg.call(d3.zoom()
                .extent([[0, 0], [width, height]])
                .scaleExtent([0.5, 2])
                .on("zoom", (event) => {
                    container.attr("transform", event.transform);
                }));

            // Create arrow marker for directed edges
            svg.append("defs").append("marker")
                .attr("id", "arrow")
                .attr("viewBox", "0 -5 10 10")
                .attr("refX", 20)
                .attr("refY", 0)
                .attr("markerWidth", 6)
                .attr("markerHeight", 6)
                .attr("orient", "auto")
                .append("path")
                .attr("d", "M0,-5L10,0L0,5")
                .attr("fill", "#999");

            const link = container.append("g")
                .attr("class", "links")
                .selectAll("line")
                .data(data.links)
                .enter().append("line")
                .attr("class", "link")
                .attr("stroke-width", 2)
                .attr("stroke", "#999")
                .attr("marker-end", "url(#arrow)");

            // Create node groups
            const nodeGroup = container.append("g")
                .attr("class", "nodes")
                .selectAll("g")
                .data(data.nodes)
                .enter().append("g")
                .attr("class", "node-group")
                .call(d3.drag()
                    .on("start", dragstarted)
                    .on("drag", dragged)
                    .on("end", dragended));

            // MODIFIED: Node coloring based on entry property
            const node = nodeGroup.append("circle")
                .attr("r", 20)
                .attr("fill", d => d.entry ? "#FF0000" : "#808080")  // Red for entry nodes, gray for non-entry
                .attr("stroke", "#000")
                .attr("stroke-width", 1.5);

            // ADDED: Legend for node colors
            const legend = svg.append("g")
                .attr("class", "legend")
                .attr("transform", "translate(20,20)");

            const legendItems = [
                { color: "#FF0000", label: "Entry Point" },
                { color: "#808080", label: "Regular Node" }
            ];

            legendItems.forEach((item, i) => {
                const legendRow = legend.append("g")
                    .attr("transform", `translate(0, ${i * 20})`);
                    
                legendRow.append("circle")
                    .attr("cx", 10)
                    .attr("cy", 10)
                    .attr("r", 7)
                    .attr("fill", item.color);
                    
                legendRow.append("text")
                    .attr("x", 30)
                    .attr("y", 15)
                    .text(item.label)
                    .style("font-size", "12px");
            });

            // Add labels with background
            const labels = nodeGroup.append("g")
                .attr("class", "label-group");

            // Add white background for labels
            labels.append("rect")
                .attr("class", "label-background")
                .attr("fill", "white")
                .attr("opacity", 0.8);

            // Add text labels
            const text = labels.append("text")
                .attr("dy", -30)
                .attr("text-anchor", "middle")
                .text(d => d.name)
                .each(function() {
                    const bbox = this.getBBox();
                    const parent = this.parentNode;
                    const rect = parent.querySelector("rect");
                    rect.setAttribute("x", bbox.x - 5);
                    rect.setAttribute("y", bbox.y - 2);
                    rect.setAttribute("width", bbox.width + 10);
                    rect.setAttribute("height", bbox.height + 4);
                });

            // Update positions on simulation tick
            simulation.on("tick", () => {
                link
                    .attr("x1", d => d.source.x)
                    .attr("y1", d => d.source.y)
                    .attr("x2", d => d.target.x)
                    .attr("y2", d => d.target.y);

                nodeGroup
                    .attr("transform", d => `translate(${d.x},${d.y})`);
            });

            // Drag functions
            function dragstarted(event, d) {
                if (!event.active) simulation.alphaTarget(0.3).restart();
                d.fx = d.x;
                d.fy = d.y;
            }

            function dragged(event, d) {
                d.fx = event.x;
                d.fy = event.y;
            }

            function dragended(event, d) {
                if (!event.active) simulation.alphaTarget(0);
                d.fx = null;
                d.fy = null;
            }

            // Handle blueprint options
            const blueprint_options = $("#blueprint_options");
            console.log(data.options);
            for (const [option, value] of Object.entries(data.options)) {
                const option_div = $("<div></div>").text(`${option}:`);
                const input = $("<input>");
                input.attr("type", "text");
                input.val(`${value}`);
                option_div.append(input);
                blueprint_options.append(option_div);
                input.on("change", event => {
                    console.log(input.val());
                    event.preventDefault();
                    $.post({
                        url: `/api/set_blueprint_option?id=${blueprint_id}&option=${option}`,
                        data: input.val(),
                        contentType: "application/json",
                    });
                });
            }
        }
    });
}
window.get_blueprint_component_graph = get_blueprint_component_graph;

// function get_blueprint_component_graph(blueprint_id) {
//     $("#blueprint_graph").empty();
//     $("#blueprint_options").empty();
//     $.ajax({
//         url: "/api/get_blueprint",
//         data: {
//             "id": blueprint_id,
//         },
//         success: function (result) {
//             if (result["error"] !== undefined) {
//                 console.log(result["error"]);
//                 return;
//             }

//             const data = result["component_graph"];
//             const width = 1400;
//             const height = 400; // Increased height for better spacing

//             const svg = d3.select("#blueprint_graph")
//                 .append("svg")
//                 .attr("width", width)
//                 .attr("height", height);

//             // Create force simulation
//             const simulation = d3.forceSimulation(data.nodes)
//                 .force("link", d3.forceLink(data.links)
//                     .id(d => d.id)
//                     .distance(150)) // Increased link distance
//                 .force("charge", d3.forceManyBody()
//                     .strength(-300)) // Increased repulsion
//                 .force("center", d3.forceCenter(width / 2, height / 2))
//                 .force("collision", d3.forceCollide().radius(50)); // Added collision detection

//             const color = d3.scaleOrdinal(d3.schemeCategory10);

//             // Create container for graph elements with zoom capability
//             const container = svg.append("g");
            
//             // Add zoom behavior
//             svg.call(d3.zoom()
//                 .extent([[0, 0], [width, height]])
//                 .scaleExtent([0.5, 2])
//                 .on("zoom", (event) => {
//                     container.attr("transform", event.transform);
//                 }));

//             // Create arrow marker for directed edges
//             svg.append("defs").append("marker")
//                 .attr("id", "arrow")
//                 .attr("viewBox", "0 -5 10 10")
//                 .attr("refX", 20)
//                 .attr("refY", 0)
//                 .attr("markerWidth", 6)
//                 .attr("markerHeight", 6)
//                 .attr("orient", "auto")
//                 .append("path")
//                 .attr("d", "M0,-5L10,0L0,5")
//                 .attr("fill", "#999");

//             const link = container.append("g")
//                 .attr("class", "links")
//                 .selectAll("line")
//                 .data(data.links)
//                 .enter().append("line")
//                 .attr("class", "link")
//                 .attr("stroke-width", 2)
//                 .attr("stroke", "#999")
//                 .attr("marker-end", "url(#arrow)");

//             // Create node groups
//             const nodeGroup = container.append("g")
//                 .attr("class", "nodes")
//                 .selectAll("g")
//                 .data(data.nodes)
//                 .enter().append("g")
//                 .attr("class", "node-group")
//                 .call(d3.drag()
//                     .on("start", dragstarted)
//                     .on("drag", dragged)
//                     .on("end", dragended));

//             // Add circles to node groups
//             const node = nodeGroup.append("circle")
//                 .attr("r", 20)
//                 .attr("fill", d => color(d.id));

//             // Add labels with background
//             const labels = nodeGroup.append("g")
//                 .attr("class", "label-group");

//             // Add white background for labels
//             labels.append("rect")
//                 .attr("class", "label-background")
//                 .attr("fill", "white")
//                 .attr("opacity", 0.8);

//             // Add text labels
//             const text = labels.append("text")
//                 .attr("dy", -30)
//                 .attr("text-anchor", "middle")
//                 .text(d => d.name)
//                 .each(function() {
//                     const bbox = this.getBBox();
//                     const parent = this.parentNode;
//                     const rect = parent.querySelector("rect");
//                     rect.setAttribute("x", bbox.x - 5);
//                     rect.setAttribute("y", bbox.y - 2);
//                     rect.setAttribute("width", bbox.width + 10);
//                     rect.setAttribute("height", bbox.height + 4);
//                 });

//             // Update positions on simulation tick
//             simulation.on("tick", () => {
//                 link
//                     .attr("x1", d => d.source.x)
//                     .attr("y1", d => d.source.y)
//                     .attr("x2", d => d.target.x)
//                     .attr("y2", d => d.target.y);

//                 nodeGroup
//                     .attr("transform", d => `translate(${d.x},${d.y})`);
//             });

//             // Drag functions
//             function dragstarted(event, d) {
//                 if (!event.active) simulation.alphaTarget(0.3).restart();
//                 d.fx = d.x;
//                 d.fy = d.y;
//             }

//             function dragged(event, d) {
//                 d.fx = event.x;
//                 d.fy = event.y;
//             }

//             function dragended(event, d) {
//                 if (!event.active) simulation.alphaTarget(0);
//                 d.fx = null;
//                 d.fy = null;
//             }

//             // Handle blueprint options
//             const blueprint_options = $("#blueprint_options");
//             console.log(data.options);
//             for (const [option, value] of Object.entries(data.options)) {
//                 const option_div = $("<div></div>").text(`${option}:`);
//                 const input = $("<input>");
//                 input.attr("type", "text");
//                 input.val(`${value}`);
//                 option_div.append(input);
//                 blueprint_options.append(option_div);
//                 input.on("change", event => {
//                     console.log(input.val());
//                     event.preventDefault();
//                     $.post({
//                         url: `/api/set_blueprint_option?id=${blueprint_id}&option=${option}`,
//                         data: input.val(),
//                         contentType: "application/json",
//                     });
//                 });
//             }
//         }
//     });
// }
// window.get_blueprint_component_graph = get_blueprint_component_graph;

// Initialize on document load
document.addEventListener('DOMContentLoaded', function() {
    initializeBlueprintSelection();
    updateSearchButtonState();
    clearSearchResults();
});

// Make functions available globally
window.searchForCPVs = searchForCPVs;
window.showCPVDetails = showCPVDetails;
window.toggleDetail = toggleDetail;