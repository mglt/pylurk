import pandas as pd
import matplotlib
# prevent error when plotting from the use of the tkinter module
matplotlib.use('agg')
import matplotlib.pyplot as plt


def boxplot (sheet_name, excel_file, graph_params, fig_path):
    '''
    This method provides a boxplot graph of the data specified in the sheet_name of the specified excel_file based on the graph_params and save the graph in the specifed
    fig_path. It can also group different boxes together
    :param sheet_name: name of the sheet in the excel file containing the data to plot
    :param excel_file: path to the excel file containing the data to plot
    :param graph_params: a dictionary with different parameters and the data to plot as follows:
        graph_params = {'title': 'Authentication Methods',
                'xlabel':'Authentication Methods',
                'ylabel': 'Latency (sec)',
                'box_width':0.5, #width of each box in the graph
                'start_position':1, #the position of the first box to draw
                'show_grid':True, #show grid in the graph
                'legend':{
                    'location':'lower right', #location of the legend. Can take one of the following values:'best','upper right','upper left','lower left','lower right','right','center left','center right','lower center','upper center','center'
                    'font_properties':{
                        # 'fontname':'Calibri',
                        'size': '12',
                        #'weight': 'bold',
                    }
                },
                'font_properties':{#font properties of title, ylabel and xlabel
                   #'fontname':'Calibri',
                   'size':'14',
                   'weight':'bold',
                },
                'ticks_font_properties': {
                    # 'fontname':'Calibri',
                    'size': '12',
                    #'weight': 'bold',
                },
                #data to plot grouped into multiple group. if no group is desired, a dictionary for each data to plot should be added
                'groups': [
                    {  'tick_label':'RSA', #label on xaxis depicting all the data in data
                       'color': ['blue', 'green'],#color of the box of each data in data, set 'White if no color is desired
                       'hatch': ['/','o','*'],# pattern of each box in data. Set '' if no hatch is desired. It can take one of the following patterns = ('-', '+', 'x', '\\', '*', 'o', 'O', '.', '/')
                       'data': ['rsa_master_prf_sha384_pfs_sha256','rsa_master_prf_sha512_pfs_sha256'],#colummn name of the data to plot as defined in excel sheet
                       'legends': ['(prf = sha384, pfs = sha256)','(prf = sha512, pfs = sha256)']#legend corresponding to each data, set None if no legend to be added to a specified data or provide an empty list
                    },
                    {   'tick_label':'RSA_Extended',
                        'color': ['blue', 'green'],#same color and hatch as previous group to have same legend
                        'hatch': ['/','o','*'],
                        'data': ['rsa_extended_master_prf_sha384_pfs_sha256','rsa_extended_master_prf_sha512_pfs_sha256'],
                        'legends': [],#empty list to have one legend per color as specified in previous group
                    },
                    {   'tick_label':'ECDHE',
                        'color': ['red'],
                        'hatch': ['+'],
                        'data': ['ecdhe_sig_sha512rsa_pfs_sha256'],
                        'legends': ['sig_and_hash = (sha256, rsa)'],
                    },

                ]}
    :param fig_path: path to the figure where the graph should be saved
    :return:
    '''

    try:
        # read the sheet containing the values that we want to plot
        df = pd.read_excel(excel_file, sheet_name=sheet_name, engine=None)

        handlers= [] #boxes corresponding to legend list
        legends =[] #legends list
        ticks = [] #xticks positions
        labels =[] #labels at the specified xticks

        count =0

        #postion at which the box should be drawn
        pos=graph_params['start_position']

        #specify that we want to perform several plots
        fig, ax = plt.subplots()

        # loop over the different groups to plot
        for group_info in graph_params['groups']:

            tick =pos

            #loop over the data to plot in each group
            for data_plot in group_info['data']:
                #draw a box for each data
                box = ax.boxplot(df[data_plot], positions=[pos], widths=graph_params['box_width'],
                              patch_artist=True, boxprops=dict(facecolor=group_info['color'][count], hatch=group_info['hatch'][count]), medianprops=dict(color='black', linewidth=2) )
                #add legends and handlers for each box, only if provided
                try:
                   if group_info['legends'][count]!= None:
                     legends.append(group_info['legends'][count])
                     handlers.append(box["boxes"][0])
                except:
                    pass

                count +=1
                #make sure that boxes in the same group are group together
                pos = pos+graph_params['box_width']

            #set the label for each group in the middle of all the boxes of the group
            tick = (2*tick+(len(group_info['data'])-1)*graph_params['box_width'])/2
            ticks.append(tick)
            labels.append(group_info['tick_label'])

            count = 0
            #leave a space of 1 between the boxes of different groups
            pos = pos+1

        #add the legend and specify its location
        ax.legend(handlers, legends, loc=graph_params['legend']['location'], prop=matplotlib.font_manager.FontProperties(**graph_params['legend']['font_properties']))

        #show grid
        plt.grid(b= graph_params['show_grid'], color='grey', linestyle='-', linewidth=0.25)
        #set the length of xaxis
        plt.xlim(0, pos+1)
        #add a label for xaxis
        plt.xlabel(graph_params['xlabel'],**graph_params['font_properties'])
        #add label for yaxis
        plt.ylabel(graph_params['ylabel'], **graph_params['font_properties'])
        #add title for the figure
        plt.title(graph_params['title'],**graph_params['font_properties'])
        #set the labels on xaxis
        plt.xticks(ticks=ticks, labels=labels,**graph_params['ticks_font_properties'])
        # set font for yaxis ticks
        plt.yticks(**graph_params['ticks_font_properties'])
        #save the graph
        plt.savefig(fig_path)
    except FileNotFoundError:
        print ("Excel File %s or graph  path %s is not found to read data and generate graph"%excel_file,fig_path )

